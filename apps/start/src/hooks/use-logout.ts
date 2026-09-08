import { useTRPC } from '@/integrations/trpc/react';
import { useMutation } from '@tanstack/react-query';

export function useLogout() {
  const trpc = useTRPC();
  const signOut = useMutation(
    trpc.auth.signOut.mutationOptions({
      onSuccess() {
        // `noredirect` so AUTH_AUTO_REDIRECT doesn't sign them back in.
        window.location.href = '/login?noredirect=1';
      },
    }),
  );
  return signOut;
}
