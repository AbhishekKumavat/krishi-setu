
import type { Metadata } from 'next';
import { AppLayout } from '@/components/layout/app-layout';
import { Toaster } from '@/components/ui/toaster';
import './globals.css';
import { ThemeProvider } from '@/components/layout/theme-provider';
import { CartProvider } from '@/context/cart-provider';
import { SearchProvider } from '@/context/search-provider';
import { UserProfileDialogProvider } from '@/context/user-profile-dialog-provider';
import { SessionProvider } from 'next-auth/react';
import { auth } from '@/auth';
import Script from 'next/script';

export const metadata: Metadata = {
  title: 'KrishiSetu AI: Grow Together',
  description:
    'An agriculture platform for farmers combining community, ecommerce, and ML-driven insights.',
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const session = await auth();

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=Noto+Sans:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="font-body antialiased">
        <SessionProvider session={session}>
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            disableTransitionOnChange
          >
            <UserProfileDialogProvider>
              <CartProvider>
                <SearchProvider>
                  <AppLayout>{children}</AppLayout>
                </SearchProvider>
              </CartProvider>
            </UserProfileDialogProvider>
            <Toaster />
          </ThemeProvider>
        </SessionProvider>

        <div id="google_translate_element" className="hidden"></div>
        <Script
          src="https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"
          strategy="afterInteractive"
        />
        <Script id="google-translate-config" strategy="afterInteractive">
          {`
            function googleTranslateElementInit() {
              new window.google.translate.TranslateElement({ pageLanguage: 'en', autoDisplay: false }, 'google_translate_element');
            }
          `}
        </Script>
      </body>
    </html>
  );
}
