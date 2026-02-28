'use client';
import { useSession, signOut as nextAuthSignOut } from 'next-auth/react';

export function useUser() {
    const { data: session, status } = useSession();

    const user = session?.user
        ? {
            uid: session.user.id as string,
            email: session.user.email ?? '',
            displayName: session.user.name ?? '',
            photoURL: session.user.image ?? null,
            username: (session.user as any).username ?? '',
            role: (session.user as any).role ?? 'user',
            region: (session.user as any).region ?? '',
            isVerified: (session.user as any).isVerified ?? false,
        }
        : null;

    return {
        user,
        loading: status === 'loading',
        isAuthenticated: status === 'authenticated',
    };
}

export async function signOutUser() {
    await nextAuthSignOut({ callbackUrl: '/' });
}
