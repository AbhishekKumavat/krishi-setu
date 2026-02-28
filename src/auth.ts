import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { db } from '@/db';
import { users } from '@/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';

export const { handlers, auth, signIn, signOut } = NextAuth({
    session: { strategy: 'jwt' },
    secret: process.env.AUTH_SECRET,
    pages: {
        signIn: '/login',
    },
    providers: [
        Credentials({
            name: 'credentials',
            credentials: {
                email: { label: 'Email', type: 'email' },
                password: { label: 'Password', type: 'password' },
            },
            async authorize(credentials) {
                if (!credentials?.email || !credentials?.password) return null;

                const [user] = await db
                    .select()
                    .from(users)
                    .where(eq(users.email, credentials.email as string))
                    .limit(1);

                if (!user) return null;

                const passwordMatch = await bcrypt.compare(
                    credentials.password as string,
                    user.passwordHash
                );

                if (!passwordMatch) return null;

                return {
                    id: user.id,
                    email: user.email,
                    name: user.displayName,
                    image: user.photoURL,
                    username: user.username,
                    role: user.role,
                    region: user.region,
                    isVerified: user.isVerified,
                };
            },
        }),
    ],
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id;
                token.username = (user as any).username;
                token.role = (user as any).role;
                token.region = (user as any).region;
                token.isVerified = (user as any).isVerified;
            }
            return token;
        },
        async session({ session, token }) {
            if (session.user) {
                session.user.id = token.id as string;
                (session.user as any).username = token.username;
                (session.user as any).role = token.role;
                (session.user as any).region = token.region;
                (session.user as any).isVerified = token.isVerified;
            }
            return session;
        },
    },
});
