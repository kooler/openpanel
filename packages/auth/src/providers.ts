import { type OidcConfig, oidcConfig } from './oidc';

/** Which login providers are configured, and whether to skip straight to one. */

type AuthEnv = Record<string, string | undefined>;

export type AuthProviderId = 'google' | 'github' | 'oidc';

export interface ConfiguredAuthProviders {
  google: boolean;
  github: boolean;
  oidc: false | { name: string };
  /** Set only when AUTH_AUTO_REDIRECT is on and exactly one provider exists. */
  autoRedirect: AuthProviderId | null;
}

// Explicit comparison, so the string "false" is not read as on.
function isFlagEnabled(value: string | undefined): boolean {
  return value === 'true' || value === '1';
}

function resolveAuthProviders(env: AuthEnv, config: OidcConfig | null) {
  const enabled: AuthProviderId[] = [];
  if (env.GOOGLE_CLIENT_ID) {
    enabled.push('google');
  }
  if (env.GITHUB_CLIENT_ID) {
    enabled.push('github');
  }
  if (config) {
    enabled.push('oidc');
  }

  const warnings: string[] = [];
  let autoRedirect: AuthProviderId | null = null;

  if (isFlagEnabled(env.AUTH_AUTO_REDIRECT)) {
    if (enabled.length === 1) {
      autoRedirect = enabled[0]!;
    } else {
      warnings.push(
        `AUTH_AUTO_REDIRECT is enabled but ${enabled.length} login providers are configured (${enabled.join(', ') || 'none'}). It only applies when exactly one is configured, so the login page will render normally.`
      );
    }
  }

  const providers: ConfiguredAuthProviders = {
    google: enabled.includes('google'),
    github: enabled.includes('github'),
    oidc: config ? { name: config.name } : false,
    autoRedirect,
  };

  return { providers, warnings };
}

/** Public shape sent to the login page. Contains no secrets. */
export function getConfiguredAuthProviders(
  env: AuthEnv = process.env,
  config: OidcConfig | null = oidcConfig
): ConfiguredAuthProviders {
  return resolveAuthProviders(env, config).providers;
}

/** Surfaced once at boot, not on every request. */
export function getAuthProviderWarnings(
  env: AuthEnv = process.env,
  config: OidcConfig | null = oidcConfig
): string[] {
  return resolveAuthProviders(env, config).warnings;
}
