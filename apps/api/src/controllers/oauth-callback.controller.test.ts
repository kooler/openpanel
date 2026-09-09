/**
 * Security properties of the OIDC callback: state and PKCE verifier are both
 * required before a code exchange, an unverified email is refused, and
 * account matching never falls back to email.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  accountFindFirst,
  userCreate,
  userFindFirst,
  createSessionMock,
  setSessionTokenCookieMock,
  validateAuthorizationCodeMock,
  getIsRegistrationAllowedMock,
} = vi.hoisted(() => ({
  accountFindFirst: vi.fn(),
  userCreate: vi.fn(),
  userFindFirst: vi.fn(),
  createSessionMock: vi.fn(),
  setSessionTokenCookieMock: vi.fn(),
  validateAuthorizationCodeMock: vi.fn(),
  getIsRegistrationAllowedMock: vi.fn(),
}));

vi.mock('@openpanel/auth', () => ({
  Arctic: { decodeIdToken: vi.fn() },
  createSession: createSessionMock,
  generateSessionToken: () => 'session-token',
  github: {},
  google: {},
  oidc: { validateAuthorizationCode: validateAuthorizationCodeMock },
  oidcConfig: {
    clientId: 'openpanel',
    clientSecret: 'secret',
    redirectUri: 'http://localhost:3333/oauth/oidc/callback',
    authorizationEndpoint: 'http://idp.test/authorize',
    tokenEndpoint: 'http://idp.test/token',
    userinfoEndpoint: 'http://idp.test/userinfo',
    scopes: ['openid', 'profile', 'email'],
    name: 'Keycloak',
  },
  setLastAuthProviderCookie: vi.fn(),
  setSessionTokenCookie: setSessionTokenCookieMock,
}));

vi.mock('@openpanel/db', () => ({
  db: {
    account: { findFirst: accountFindFirst, update: vi.fn() },
    user: { create: userCreate, findFirst: userFindFirst },
  },
  connectUserToOrganization: vi.fn(),
  getIsRegistrationAllowed: getIsRegistrationAllowedMock,
}));

const { mapOidcUser, oidcCallback } = await import(
  './oauth-callback.controller'
);

function makeReply() {
  const redirect = vi.fn();
  const reply = {
    redirect,
    clearCookie: vi.fn(),
    setCookie: vi.fn(),
    log: { error: vi.fn() },
    request: { id: 'req-1' },
  };
  return { reply: reply as unknown as FastifyReply, redirect };
}

function makeReq(cookies: Record<string, string> = {}) {
  return {
    query: { code: 'auth-code', state: 'state-1' },
    cookies: {
      oidc_oauth_state: 'state-1',
      oidc_code_verifier: 'verifier-1',
      ...cookies,
    },
    log: { error: vi.fn() },
  } as unknown as FastifyRequest;
}

function userInfoResponse(body: unknown) {
  return {
    ok: true,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function redirectedError(redirect: ReturnType<typeof vi.fn>) {
  const url = new URL(redirect.mock.calls[0]?.[0] as string);
  return { pathname: url.pathname, error: url.searchParams.get('error') };
}

beforeEach(() => {
  vi.clearAllMocks();
  // Otherwise the fetch stub outlives its test.
  vi.unstubAllGlobals();
  vi.stubEnv('DASHBOARD_URL', 'http://localhost:3000');
  validateAuthorizationCodeMock.mockResolvedValue({
    accessToken: () => 'access-token',
  });
  getIsRegistrationAllowedMock.mockResolvedValue(true);
  accountFindFirst.mockResolvedValue(null);
  userFindFirst.mockResolvedValue(null);
  userCreate.mockResolvedValue({ id: 'user-1', email: 'ada@example.com' });
  createSessionMock.mockResolvedValue({ expiresAt: new Date() });
});

describe('mapOidcUser', () => {
  it('maps a full userinfo payload', () => {
    expect(
      mapOidcUser({
        sub: 'sub-1',
        email: 'ada@example.com',
        email_verified: true,
        given_name: 'Ada',
        family_name: 'Lovelace',
        name: 'Ada Lovelace',
      })
    ).toEqual({
      id: 'sub-1',
      email: 'ada@example.com',
      firstName: 'Ada',
      lastName: 'Lovelace',
    });
  });

  it('falls back from given_name to name to the email local part', () => {
    const base = { sub: 'sub-1', email: 'ada@example.com' };
    expect(mapOidcUser({ ...base, name: 'Ada Lovelace' }).firstName).toBe(
      'Ada Lovelace'
    );
    expect(mapOidcUser(base).firstName).toBe('ada');
  });

  it.each([
    ['sub', { email: 'ada@example.com' }],
    ['email', { sub: 'sub-1' }],
  ])('throws when %s is missing', (_claim, payload) => {
    expect(() => mapOidcUser(payload)).toThrow(/userinfo/i);
  });

  it.each([false, 'false'])(
    'rejects email_verified=%o however the provider spells it',
    (claim) => {
      expect(() =>
        mapOidcUser({
          sub: 'sub-1',
          email: 'ada@example.com',
          email_verified: claim,
        })
      ).toThrow(/verified/i);
    }
  );

  it.each([true, 'true'])(
    'accepts email_verified=%o however the provider spells it',
    (claim) => {
      // Cognito sends this claim as a string.
      expect(
        mapOidcUser({
          sub: 'sub-1',
          email: 'ada@example.com',
          email_verified: claim,
        }).id
      ).toBe('sub-1');
    }
  );

  it('treats an unrecognised email_verified value as absent', () => {
    expect(
      mapOidcUser({ sub: 'sub-1', email: 'ada@example.com', email_verified: 2 })
        .id
    ).toBe('sub-1');
  });

  it('accepts a payload with no email_verified claim', () => {
    expect(
      mapOidcUser({ sub: 'sub-1', email: 'ada@example.com' }).id
    ).toBe('sub-1');
  });
});

describe('oidcCallback', () => {
  it('refuses a state that does not match the cookie', async () => {
    const { reply, redirect } = makeReply();

    await oidcCallback(makeReq({ oidc_oauth_state: 'other-state' }), reply);

    expect(validateAuthorizationCodeMock).not.toHaveBeenCalled();
    expect(createSessionMock).not.toHaveBeenCalled();
    expect(setSessionTokenCookieMock).not.toHaveBeenCalled();
    expect(redirectedError(redirect)).toEqual({
      pathname: '/login',
      error: 'OAuth state mismatch',
    });
  });

  it('refuses a callback with no PKCE verifier cookie', async () => {
    const { reply, redirect } = makeReply();
    const req = makeReq();
    (req.cookies as Record<string, string | undefined>).oidc_code_verifier =
      undefined;

    await oidcCallback(req, reply);

    expect(validateAuthorizationCodeMock).not.toHaveBeenCalled();
    expect(setSessionTokenCookieMock).not.toHaveBeenCalled();
    expect(redirectedError(redirect).pathname).toBe('/login');
  });

  it('creates no user when the provider reports an unverified email', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        userInfoResponse({
          sub: 'sub-1',
          email: 'ada@example.com',
          email_verified: false,
        })
      )
    );
    const { reply, redirect } = makeReply();

    await oidcCallback(makeReq(), reply);

    expect(userCreate).not.toHaveBeenCalled();
    expect(setSessionTokenCookieMock).not.toHaveBeenCalled();
    expect(redirectedError(redirect).error).toMatch(/verified/i);
  });

  it('matches on provider and subject only, never on email', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          userInfoResponse({ sub: 'sub-1', email: 'ada@example.com' })
        )
    );
    const { reply } = makeReply();

    await oidcCallback(makeReq(), reply);

    expect(accountFindFirst).toHaveBeenCalledTimes(1);
    expect(accountFindFirst).toHaveBeenCalledWith({
      where: { provider: 'oidc', providerId: 'sub-1' },
    });
    expect(JSON.stringify(accountFindFirst.mock.calls[0])).not.toContain(
      'ada@example.com'
    );
  });

  it('sends the access token to the userinfo endpoint as a bearer token', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        userInfoResponse({ sub: 'sub-1', email: 'ada@example.com' })
      );
    vi.stubGlobal('fetch', fetchMock);
    const { reply } = makeReply();

    await oidcCallback(makeReq(), reply);

    expect(validateAuthorizationCodeMock).toHaveBeenCalledWith(
      'http://idp.test/token',
      'auth-code',
      'verifier-1'
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'http://idp.test/userinfo',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer access-token',
        }),
      })
    );
  });
});
