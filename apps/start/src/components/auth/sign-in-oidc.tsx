import { useMutation } from '@tanstack/react-query';
import { KeyRoundIcon } from 'lucide-react';
import { useTRPC } from '@/integrations/trpc/react';
import { Button } from '../ui/button';

export function SignInOidc({
  type,
  name,
  inviteId,
  isLastUsed,
}: {
  type: 'sign-in' | 'sign-up';
  name: string;
  inviteId?: string;
  isLastUsed?: boolean;
}) {
  const trpc = useTRPC();
  const mutation = useMutation(
    trpc.auth.signInOAuth.mutationOptions({
      onSuccess(res) {
        if (res.url) {
          window.location.href = res.url;
        }
      },
    })
  );

  const title = type === 'sign-up' ? `Sign up with ${name}` : `Sign in with ${name}`;

  return (
    <div className="relative">
      <Button
        className="w-full border border-def-300 bg-background text-foreground shadow-sm transition-all duration-200 hover:bg-def-100 hover:shadow-md [&_svg]:shrink-0"
        loading={mutation.isPending}
        onClick={() =>
          mutation.mutate({
            provider: 'oidc',
            inviteId,
          })
        }
        size="lg"
      >
        <KeyRoundIcon className="mr-2 size-4" />
        {title}
      </Button>
      {isLastUsed && (
        <span className="absolute -top-2 right-3 rounded-full bg-highlight px-1.5 py-0.5 font-medium text-[10px] text-white leading-none">
          Used last time
        </span>
      )}
    </div>
  );
}
