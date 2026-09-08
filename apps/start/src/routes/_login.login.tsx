import { useMutation, useQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { AlertCircle } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { z } from 'zod';
import { Or } from '@/components/auth/or';
import { SignInEmailForm } from '@/components/auth/sign-in-email-form';
import { SignInGithub } from '@/components/auth/sign-in-github';
import { SignInGoogle } from '@/components/auth/sign-in-google';
import { SignInOidc } from '@/components/auth/sign-in-oidc';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useCookieStore } from '@/hooks/use-cookie-store';
import { useTRPC } from '@/integrations/trpc/react';
import { createTitle, PAGE_TITLES } from '@/utils/title';

export const Route = createFileRoute('/_login/login')({
  component: LoginPage,
  head: () => ({
    meta: [
      { title: createTitle(PAGE_TITLES.LOGIN) },
      { name: 'robots', content: 'noindex, follow' },
    ],
  }),
  validateSearch: z.object({
    error: z.string().optional(),
    correlationId: z.string().optional(),
    inviteId: z.string().optional(),
    // Escape hatch out of AUTH_AUTO_REDIRECT. Only presence is read; the type
    // is unconstrained because the router JSON-parses search values and a
    // narrower schema would send this page to the error boundary.
    noredirect: z.unknown().optional(),
  }),
  loader: async ({ context }) => {
    await context.queryClient.prefetchQuery(
      context.trpc.auth.authProviders.queryOptions()
    );
  },
});

function LoginPage() {
  const { error, correlationId, inviteId, noredirect } = Route.useSearch();
  const trpc = useTRPC();
  const [lastProvider] = useCookieStore<null | string>(
    'last-auth-provider',
    null
  );
  const { data: providers } = useQuery(
    trpc.auth.authProviders.queryOptions()
  );
  const signInOAuth = useMutation(
    trpc.auth.signInOAuth.mutationOptions({
      onSuccess(res) {
        if (res.url) {
          window.location.href = res.url;
        }
      },
    })
  );

  const autoRedirect = providers?.autoRedirect ?? null;
  // A failed login must not bounce back to the provider, or it loops.
  const skipAutoRedirect = error !== undefined || noredirect !== undefined;
  const hasStartedRedirect = useRef(false);
  const startRedirect = signInOAuth.mutate;

  useEffect(() => {
    if (!autoRedirect || skipAutoRedirect || hasStartedRedirect.current) {
      return;
    }
    hasStartedRedirect.current = true;
    startRedirect({ provider: autoRedirect, inviteId });
  }, [autoRedirect, skipAutoRedirect, inviteId, startRedirect]);

  const hasOAuthProviders = Boolean(
    providers?.google || providers?.github || providers?.oidc
  );

  return (
    <div className="col w-full gap-8 text-left">
      <div>
        <h1 className="mb-2 font-bold text-3xl text-foreground">Sign in</h1>
        <p className="text-muted-foreground">
          Don't have an account?{' '}
          <a
            className="font-medium text-foreground underline"
            href="/onboarding"
          >
            Create one today
          </a>
        </p>
      </div>
      {error && (
        <Alert
          className="mb-6 border-destructive/20 bg-destructive/10 text-left"
          variant="destructive"
        >
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>
            <p>{error}</p>
            {correlationId && (
              <>
                <p>Correlation ID: {correlationId}</p>
                <p className="mt-2">
                  Contact us if you have any issues.{' '}
                  <a
                    className="font-medium underline"
                    href={`mailto:hello@openpanel.dev?subject=Login%20Issue%20-%20Correlation%20ID%3A%20${correlationId}`}
                  >
                    hello[at]openpanel.dev
                  </a>
                </p>
              </>
            )}
          </AlertDescription>
        </Alert>
      )}

      {hasOAuthProviders && (
        <>
          <div className="space-y-4">
            {providers?.google && (
              <SignInGoogle
                inviteId={inviteId}
                isLastUsed={lastProvider === 'google'}
                type="sign-in"
              />
            )}
            {providers?.github && (
              <SignInGithub
                inviteId={inviteId}
                isLastUsed={lastProvider === 'github'}
                type="sign-in"
              />
            )}
            {providers?.oidc && (
              <SignInOidc
                inviteId={inviteId}
                isLastUsed={lastProvider === 'oidc'}
                name={providers.oidc.name}
                type="sign-in"
              />
            )}
          </div>
          <Or />
        </>
      )}
      <SignInEmailForm inviteId={inviteId} isLastUsed={lastProvider === 'email'} />
    </div>
  );
}
