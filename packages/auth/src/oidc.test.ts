import { describe, expect, it } from 'vitest';
import { loadOidcConfig, parseOidcScopes } from './oidc';

const FULL_ENV = {
  OIDC_CLIENT_ID: 'openpanel',
  OIDC_CLIENT_SECRET: 'secret',
  OIDC_REDIRECT_URI: 'http://localhost:3333/oauth/oidc/callback',
  OIDC_AUTHORIZATION_ENDPOINT: 'https://auth.example.com/authorize',
  OIDC_TOKEN_ENDPOINT: 'http://keycloak:8080/token',
  OIDC_USERINFO_ENDPOINT: 'http://keycloak:8080/userinfo',
};

describe('loadOidcConfig', () => {
  it('is disabled when OIDC_CLIENT_ID is unset', () => {
    expect(loadOidcConfig({})).toBeNull();
    expect(loadOidcConfig({ OIDC_CLIENT_SECRET: 'secret' })).toBeNull();
  });

  it('is disabled when OIDC_CLIENT_ID is empty', () => {
    expect(loadOidcConfig({ ...FULL_ENV, OIDC_CLIENT_ID: '' })).toBeNull();
  });

  it.each([
    'OIDC_CLIENT_SECRET',
    'OIDC_REDIRECT_URI',
    'OIDC_AUTHORIZATION_ENDPOINT',
    'OIDC_TOKEN_ENDPOINT',
    'OIDC_USERINFO_ENDPOINT',
  ])('throws and names %s when it is missing', (missing) => {
    const env = { ...FULL_ENV, [missing]: undefined };
    expect(() => loadOidcConfig(env)).toThrow(missing);
  });

  it('reads every endpoint, allowing internal token/userinfo urls', () => {
    const config = loadOidcConfig(FULL_ENV);
    expect(config).toMatchObject({
      clientId: 'openpanel',
      clientSecret: 'secret',
      authorizationEndpoint: 'https://auth.example.com/authorize',
      tokenEndpoint: 'http://keycloak:8080/token',
      userinfoEndpoint: 'http://keycloak:8080/userinfo',
    });
  });

  it('defaults the button name to SSO', () => {
    expect(loadOidcConfig(FULL_ENV)?.name).toBe('SSO');
    expect(loadOidcConfig({ ...FULL_ENV, OIDC_NAME: 'Keycloak' })?.name).toBe(
      'Keycloak'
    );
  });
});

describe('parseOidcScopes', () => {
  it('defaults to the standard OIDC scopes', () => {
    expect(parseOidcScopes(undefined)).toEqual(['openid', 'profile', 'email']);
  });

  it('splits on whitespace', () => {
    expect(parseOidcScopes('openid  email\tgroups')).toEqual([
      'openid',
      'email',
      'groups',
    ]);
  });

  it('yields no scopes when explicitly empty', () => {
    // OAuth2-only servers reject the `openid` scope.
    expect(parseOidcScopes('')).toEqual([]);
    expect(parseOidcScopes('   ')).toEqual([]);
  });
});
