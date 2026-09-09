import {
  Arctic,
  COOKIE_OPTIONS,
  createSession,
  generateSessionToken,
  github,
  google,
  type OAuth2Tokens,
  oidc,
  oidcConfig,
  setLastAuthProviderCookie,
  setSessionTokenCookie,
} from '@openpanel/auth';
import {
  type Account,
  connectUserToOrganization,
  db,
  getIsRegistrationAllowed,
} from '@openpanel/db';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { LogError } from '@/utils/errors';

async function getGithubEmail(githubAccessToken: string) {
  const emailListRequest = new Request('https://api.github.com/user/emails');
  emailListRequest.headers.set('Authorization', `Bearer ${githubAccessToken}`);
  const emailListResponse = await fetch(emailListRequest);
  const emailListResult: unknown = await emailListResponse.json();
  if (!Array.isArray(emailListResult) || emailListResult.length < 1) {
    return null;
  }
  let email: string | null = null;
  for (const emailRecord of emailListResult) {
    const emailParser = z.object({
      primary: z.boolean(),
      verified: z.boolean(),
      email: z.string(),
    });
    const emailResult = emailParser.safeParse(emailRecord);
    if (!emailResult.success) {
      continue;
    }
    if (emailResult.data.primary && emailResult.data.verified) {
      email = emailResult.data.email;
    }
  }
  return email;
}

// New types and interfaces
type Provider = 'github' | 'google' | 'oidc';

// Providers that carry a `<provider>_code_verifier` cookie into the callback.
const PKCE_PROVIDERS = new Set<Provider>(['google', 'oidc']);
interface OAuthUser {
  id: string;
  email: string;
  firstName: string;
  lastName?: string;
}

// Shared utility functions
async function handleExistingUser({
  account,
  oauthUser,
  providerName,
  inviteId,
  reply,
}: {
  account: Account;
  oauthUser: OAuthUser;
  providerName: Provider;
  inviteId: string | undefined | null;
  reply: FastifyReply;
}) {
  const sessionToken = generateSessionToken();
  const session = await createSession(sessionToken, account.userId);

  await db.account.update({
    where: { id: account.id },
    data: {
      provider: providerName,
      providerId: oauthUser.id,
      email: oauthUser.email,
    },
  });

  if (inviteId) {
    try {
      const user = await db.user.findUniqueOrThrow({
        where: { id: account.userId },
      });
      await connectUserToOrganization({ user, inviteId });
    } catch (error) {
      reply.log.error(
        {
          error,
          inviteId,
          userId: account.userId,
        },
        'error connecting existing user to organization'
      );
    }
  }

  setSessionTokenCookie(
    (...args) => reply.setCookie(...args),
    sessionToken,
    session.expiresAt
  );
  setLastAuthProviderCookie(
    (...args) => reply.setCookie(...args),
    providerName
  );
  return reply.redirect(
    process.env.DASHBOARD_URL || process.env.NEXT_PUBLIC_DASHBOARD_URL!
  );
}

async function handleNewUser({
  oauthUser,
  providerName,
  inviteId,
  reply,
}: {
  oauthUser: OAuthUser;
  providerName: Provider;
  inviteId: string | undefined | null;
  reply: FastifyReply;
}) {
  const existingUser = await db.user.findFirst({
    where: { email: oauthUser.email },
  });

  if (existingUser) {
    throw new LogError(
      'Please sign in using your original authentication method',
      {
        existingUser,
        oauthUser,
        providerName,
      }
    );
  }

  // Enforce the self-hosting registration policy here rather than before the
  // IdP redirect — this is the first point where we know the user is new, so
  // returning users are never caught by it.
  if (!(await getIsRegistrationAllowed(inviteId))) {
    // Deliberately no `oauthUser` here — this rejects people who are not users,
    // so their email and name shouldn't land in application logs. The redirect
    // carries `correlationId` (the request id), which is what ties a user's
    // error page back to this log line if an operator needs to investigate.
    throw new LogError('Registrations are not allowed', {
      providerName,
      inviteId,
    });
  }

  const user = await db.user.create({
    data: {
      email: oauthUser.email,
      firstName: oauthUser.firstName,
      lastName: oauthUser.lastName,
      accounts: {
        create: {
          provider: providerName,
          providerId: oauthUser.id,
        },
      },
    },
  });

  if (inviteId) {
    try {
      await connectUserToOrganization({ user, inviteId });
    } catch (error) {
      reply.log.error({
        error,
        inviteId,
        user,
      }, 'error connecting user to organization');
    }
  }

  const sessionToken = generateSessionToken();
  const session = await createSession(sessionToken, user.id);
  setSessionTokenCookie(
    (...args) => reply.setCookie(...args),
    sessionToken,
    session.expiresAt
  );
  setLastAuthProviderCookie(
    (...args) => reply.setCookie(...args),
    providerName
  );
  return reply.redirect(
    process.env.DASHBOARD_URL || process.env.NEXT_PUBLIC_DASHBOARD_URL!
  );
}

// Provider-specific user fetching
async function fetchGithubUser(accessToken: string): Promise<OAuthUser> {
  const email = await getGithubEmail(accessToken);
  if (!email) {
    throw new LogError('GitHub email not found or not verified');
  }

  const userRequest = new Request('https://api.github.com/user');
  userRequest.headers.set('Authorization', `Bearer ${accessToken}`);
  const userResponse = await fetch(userRequest);

  const userSchema = z.object({
    id: z.number(),
    login: z.string(),
    name: z
      .string()
      .nullish()
      .transform((val) => val || ''),
  });
  const userJson = await userResponse.json();

  const userResult = userSchema.safeParse(userJson);
  if (!userResult.success) {
    throw new LogError('Error fetching Github user', {
      error: userResult.error,
      githubUser: userJson,
    });
  }

  return {
    id: String(userResult.data.id),
    email,
    firstName: userResult.data.name || userResult.data.login || '',
  };
}

async function fetchGoogleUser(tokens: OAuth2Tokens): Promise<OAuthUser> {
  const claims = Arctic.decodeIdToken(tokens.idToken());

  const claimsSchema = z.object({
    sub: z.string(),
    email: z.string(),
    email_verified: z.boolean(),
    given_name: z.string().optional(),
    family_name: z.string().optional(),
  });

  const claimsResult = claimsSchema.safeParse(claims);
  if (!claimsResult.success) {
    throw new LogError('Error fetching Google user', {
      error: claimsResult.error,
      claims,
    });
  }

  if (!claimsResult.data.email_verified) {
    throw new LogError('Email not verified with Google');
  }

  return {
    id: claimsResult.data.sub,
    email: claimsResult.data.email,
    firstName: claimsResult.data.given_name || '',
    lastName: claimsResult.data.family_name || '',
  };
}

const oidcUserInfoSchema = z.object({
  sub: z.string().min(1),
  email: z.string().min(1),
  // Unknown because some providers (Cognito) send this as a string.
  email_verified: z.unknown().optional(),
  name: z.string().nullish(),
  given_name: z.string().nullish(),
  family_name: z.string().nullish(),
});

/** Only an explicit false rejects a login; anything else counts as absent. */
function isEmailExplicitlyUnverified(claim: unknown): boolean {
  return claim === false || claim === 'false';
}

/**
 * Claims come from userinfo rather than the id_token: a compliant server may
 * put only `sub` in the token, which would then need a merge step.
 */
export function mapOidcUser(payload: unknown): OAuthUser {
  const result = oidcUserInfoSchema.safeParse(payload);
  if (!result.success) {
    // Field names only: the userinfo body must not reach the logs.
    throw new LogError('Invalid userinfo response from the login provider', {
      fieldErrors: result.error.flatten().fieldErrors,
    });
  }

  const claims = result.data;

  // An unverified email is an account-takeover vector, so refuse outright.
  if (isEmailExplicitlyUnverified(claims.email_verified)) {
    throw new LogError('Your login provider has not verified this email');
  }

  const emailLocalPart = claims.email.split('@')[0];

  return {
    id: claims.sub,
    email: claims.email,
    firstName:
      claims.given_name || claims.name || emailLocalPart || claims.email,
    lastName: claims.family_name || '',
  };
}

async function fetchOidcUser(accessToken: string): Promise<OAuthUser> {
  if (!oidcConfig) {
    throw new LogError('OIDC login is not configured');
  }

  const response = await fetch(oidcConfig.userinfoEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new LogError('Could not reach the login provider', {
      status: response.status,
    });
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new LogError('The login provider returned an invalid response');
  }

  return mapOidcUser(payload);
}

interface ValidatedOAuthQuery {
  code: string;
  state: string;
}

async function validateOAuthCallback(
  req: FastifyRequest,
  provider: Provider
): Promise<ValidatedOAuthQuery> {
  const schema = z.object({
    code: z.string(),
    state: z.string(),
  });

  const query = schema.safeParse(req.query);
  if (!query.success) {
    throw new LogError('Invalid callback query params', {
      error: query.error,
      query: req.query,
      provider,
    });
  }

  const { code, state } = query.data;
  const storedState = req.cookies[`${provider}_oauth_state`] ?? null;
  const usesPkce = PKCE_PROVIDERS.has(provider);
  const codeVerifier = usesPkce
    ? (req.cookies[`${provider}_code_verifier`] ?? null)
    : null;

  if (
    code === null ||
    state === null ||
    storedState === null ||
    (usesPkce && codeVerifier === null)
  ) {
    throw new LogError('Missing oauth parameters', {
      code: code === null,
      state: state === null,
      storedState: storedState === null,
      codeVerifier: usesPkce ? codeVerifier === null : undefined,
      provider,
    });
  }

  if (state !== storedState) {
    throw new LogError('OAuth state mismatch', {
      state,
      storedState,
      provider,
    });
  }

  return { code, state };
}

// Main callback handlers
export async function githubCallback(req: FastifyRequest, reply: FastifyReply) {
  try {
    const { code } = await validateOAuthCallback(req, 'github');
    const inviteId = req.cookies.inviteId;
    const tokens = await github.validateAuthorizationCode(code);
    const githubUser = await fetchGithubUser(tokens.accessToken());
    const account = await db.account.findFirst({
      where: {
        OR: [
          // To keep
          { provider: 'github', providerId: githubUser.id },
          // During migration
          { provider: 'github', providerId: null, email: githubUser.email },
          { provider: 'oauth', user: { email: githubUser.email } },
        ],
      },
    });

    reply.clearCookie('github_oauth_state');

    if (account) {
      return await handleExistingUser({
        account,
        oauthUser: githubUser,
        providerName: 'github',
        inviteId,
        reply,
      });
    }

    return await handleNewUser({
      oauthUser: githubUser,
      providerName: 'github',
      inviteId,
      reply,
    });
  } catch (error) {
    req.log.error(error);
    return redirectWithError(reply, error);
  }
}

export async function googleCallback(req: FastifyRequest, reply: FastifyReply) {
  try {
    const { code } = await validateOAuthCallback(req, 'google');
    const inviteId = req.cookies.inviteId;
    const codeVerifier = req.cookies.google_code_verifier!;
    const tokens = await google.validateAuthorizationCode(code, codeVerifier);
    const googleUser = await fetchGoogleUser(tokens);
    const existingUser = await db.account.findFirst({
      where: {
        OR: [
          // To keep
          { provider: 'google', providerId: googleUser.id },
          // During migration
          { provider: 'google', providerId: null, email: googleUser.email },
          { provider: 'oauth', user: { email: googleUser.email } },
        ],
      },
    });

    reply.clearCookie('google_code_verifier');
    reply.clearCookie('google_oauth_state');

    if (existingUser) {
      return await handleExistingUser({
        account: existingUser,
        oauthUser: googleUser,
        providerName: 'google',
        inviteId,
        reply,
      });
    }

    return await handleNewUser({
      oauthUser: googleUser,
      providerName: 'google',
      inviteId,
      reply,
    });
  } catch (error) {
    req.log.error(error);
    return redirectWithError(reply, error);
  }
}

export async function oidcCallback(req: FastifyRequest, reply: FastifyReply) {
  try {
    if (!(oidc && oidcConfig)) {
      throw new LogError('OIDC login is not configured');
    }

    const { code } = await validateOAuthCallback(req, 'oidc');
    const inviteId = req.cookies.inviteId;
    const codeVerifier = req.cookies.oidc_code_verifier!;
    const tokens = await oidc.validateAuthorizationCode(
      oidcConfig.tokenEndpoint,
      code,
      codeVerifier
    );
    const oidcUser = await fetchOidcUser(tokens.accessToken());

    // Subject only, never email: matching on email would hand an account to
    // anyone who can get the IdP to issue them that address.
    const account = await db.account.findFirst({
      where: { provider: 'oidc', providerId: oidcUser.id },
    });

    // Must match the options they were set with, or the clear misses them.
    reply.clearCookie('oidc_code_verifier', COOKIE_OPTIONS);
    reply.clearCookie('oidc_oauth_state', COOKIE_OPTIONS);

    if (account) {
      return await handleExistingUser({
        account,
        oauthUser: oidcUser,
        providerName: 'oidc',
        inviteId,
        reply,
      });
    }

    return await handleNewUser({
      oauthUser: oidcUser,
      providerName: 'oidc',
      inviteId,
      reply,
    });
  } catch (error) {
    req.log.error(error);
    return redirectWithError(reply, error);
  }
}

function redirectWithError(reply: FastifyReply, error: LogError | unknown) {
  const url = new URL(
    process.env.DASHBOARD_URL || process.env.NEXT_PUBLIC_DASHBOARD_URL!
  );
  url.pathname = '/login';
  if (error instanceof LogError) {
    url.searchParams.set('error', error.message);
  } else {
    url.searchParams.set('error', 'An error occurred');
  }
  url.searchParams.set('correlationId', reply.request.id);
  return reply.redirect(url.toString());
}
