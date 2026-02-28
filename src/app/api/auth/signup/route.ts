import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { users } from '@/db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';

export async function POST(req: NextRequest) {
    try {
        const { email, password, username, displayName, region, isFarmer } = await req.json();

        if (!email || !password || !username || !displayName) {
            return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
        }

        // Check if email or username already exists
        const [existingEmail] = await db.select().from(users).where(eq(users.email, email)).limit(1);
        if (existingEmail) {
            return NextResponse.json({ error: 'Email already in use' }, { status: 409 });
        }

        const [existingUsername] = await db.select().from(users).where(eq(users.username, username)).limit(1);
        if (existingUsername) {
            return NextResponse.json({ error: 'Username already taken' }, { status: 409 });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const [newUser] = await db
            .insert(users)
            .values({
                email,
                username,
                displayName,
                passwordHash,
                region: region || '',
                role: isFarmer ? 'farmer' : 'user',
                isVerified: false,
            })
            .returning({ id: users.id, email: users.email, username: users.username });

        return NextResponse.json({ success: true, user: newUser }, { status: 201 });
    } catch (error: any) {
        console.error('Signup error:', error);
        return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
    }
}
