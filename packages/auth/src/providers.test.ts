import { describe, expect, it } from 'vitest';
import { loadOidcConfig } from './oidc';
import {
  getAuthProviderWarnings,
  getConfiguredAuthProviders,
} from './providers';

const FULL_OIDC_ENV = {
  OIDC_CLIENT_ID: 'openpanel',
  OIDC_CLIENT_SECRET: 'secret',
  OIDC_REDIRECT_URI: 'http://localhost:3333/oauth/oidc/callback',
  OIDC_AUTHORIZATION_ENDPOINT: 'https://auth.example.com/authorize',
  OIDC_TOKEN_ENDPOINT: 'http://keycloak:8080/token',
  OIDC_USERINFO_ENDPOINT: 'http://keycloak:8080/userinfo',
};

describe('getConfiguredAuthProviders', () => {
  it('reports nothing configured on a default self-hosted install', () => {
    expect(getConfiguredAuthProviders({}, null)).toEqual({
      google: false,
      github: false,
      oidc: false,
      autoRedirect: null,
    });
  });

  it('reports google and github from their own env vars', () => {
    const providers = getConfiguredAuthProviders(
      { GOOGLE_CLIENT_ID: 'g', GITHUB_CLIENT_ID: 'gh' },
      null
    );
    expect(providers).toMatchObject({ google: true, github: true, oidc: false });
  });

  it('exposes the oidc button name and never the secret', () => {
    const config = loadOidcConfig({ ...FULL_OIDC_ENV, OIDC_NAME: 'Keycloak' });
    const providers = getConfiguredAuthProviders({}, config);
    expect(providers.oidc).toEqual({ name: 'Keycloak' });
    expect(JSON.stringify(providers)).not.toContain('secret');
  });

  it('auto-redirects when the flag is on and one provider is configured', () => {
    const config = loadOidcConfig(FULL_OIDC_ENV);
    const env = { AUTH_AUTO_REDIRECT: 'true' };
    expect(getConfiguredAuthProviders(env, config).autoRedirect).toBe('oidc');
    expect(getAuthProviderWarnings(env, config)).toEqual([]);
  });

  it('auto-redirects to google when it is the only provider', () => {
    const env = { AUTH_AUTO_REDIRECT: 'true', GOOGLE_CLIENT_ID: 'g' };
    expect(getConfiguredAuthProviders(env, null).autoRedirect).toBe('google');
  });

  it('does not auto-redirect when two providers are configured', () => {
    const config = loadOidcConfig(FULL_OIDC_ENV);
    const env = { AUTH_AUTO_REDIRECT: 'true', GOOGLE_CLIENT_ID: 'google' };
    expect(getConfiguredAuthProviders(env, config).autoRedirect).toBeNull();
    expect(getAuthProviderWarnings(env, config)).toHaveLength(1);
  });

  it('does not auto-redirect when no provider is configured', () => {
    const env = { AUTH_AUTO_REDIRECT: 'true' };
    expect(getConfiguredAuthProviders(env, null).autoRedirect).toBeNull();
    expect(getAuthProviderWarnings(env, null)).toHaveLength(1);
  });

  it.each(['false', '0', 'no', ''])(
    'treats AUTH_AUTO_REDIRECT=%o as off',
    (value) => {
      const config = loadOidcConfig(FULL_OIDC_ENV);
      const env = { AUTH_AUTO_REDIRECT: value };
      expect(getConfiguredAuthProviders(env, config).autoRedirect).toBeNull();
      expect(getAuthProviderWarnings(env, config)).toEqual([]);
    }
  );
});
