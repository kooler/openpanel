import * as Arctic from 'arctic';

/**
 * Generic OIDC login provider, configured from the environment.
 */

export interface OidcConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  scopes: string[];
  name: string;
}

type AuthEnv = Record<string, string | undefined>;

const DEFAULT_OIDC_SCOPES = ['openid', 'profile', 'email'];
const DEFAULT_OIDC_NAME = 'SSO';
const WHITESPACE = /\s+/;

/** An empty value yields no scopes, which OAuth2-only servers need. */
export function parseOidcScopes(raw: string | undefined): string[] {
  if (raw === undefined) {
    return [...DEFAULT_OIDC_SCOPES];
  }
  return raw.split(WHITESPACE).filter((scope) => scope.length > 0);
}

function requireVar(env: AuthEnv, name: string): string {
  const value = env[name];
  if (!value) {
    throw new Error(`${name} is required when OIDC_CLIENT_ID is set`);
  }
  return value;
}

/**
 * Null when unconfigured, throws when half-configured so a broken setup never boots.
 */
export function loadOidcConfig(env: AuthEnv = process.env): OidcConfig | null {
  if (!env.OIDC_CLIENT_ID) {
    return null;
  }

  return {
    clientId: env.OIDC_CLIENT_ID,
    clientSecret: requireVar(env, 'OIDC_CLIENT_SECRET'),
    redirectUri: requireVar(env, 'OIDC_REDIRECT_URI'),
    authorizationEndpoint: requireVar(env, 'OIDC_AUTHORIZATION_ENDPOINT'),
    tokenEndpoint: requireVar(env, 'OIDC_TOKEN_ENDPOINT'),
    userinfoEndpoint: requireVar(env, 'OIDC_USERINFO_ENDPOINT'),
    scopes: parseOidcScopes(env.OIDC_SCOPES),
    name: env.OIDC_NAME || DEFAULT_OIDC_NAME,
  };
}

export const oidcConfig = loadOidcConfig();

export const oidc = oidcConfig
  ? new Arctic.OAuth2Client(
      oidcConfig.clientId,
      oidcConfig.clientSecret,
      oidcConfig.redirectUri
    )
  : null;
