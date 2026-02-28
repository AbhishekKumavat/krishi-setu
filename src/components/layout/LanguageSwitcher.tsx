
'use client';

import { Languages } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useEffect, useState } from 'react';

export default function LanguageSwitcher() {
  const [currentLocale, setCurrentLocale] = useState('en');

  useEffect(() => {
    // Read Google Translate Cookie
    const match = document.cookie.match(/(^|;) ?googtrans=([^;]*)(;|$)/);
    if (match && match[2]) {
      const parts = decodeURIComponent(match[2]).split('/');
      if (parts.length >= 3) {
        setCurrentLocale(parts[2] || 'en');
      }
    }
  }, []);

  const changeLanguage = (lang: string) => {
    if (lang === 'en') {
      // Clear cookies to revert back to English baseline
      document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; domain=.${window.location.hostname}; path=/;`;
    } else {
      // Set cookies locally for the API to render dynamically on DOM initialization
      document.cookie = `googtrans=/en/${lang}; path=/`;
      document.cookie = `googtrans=/en/${lang}; domain=.${window.location.hostname}; path=/`;
    }
    window.location.reload();
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <Languages className="h-5 w-5" />
          <span className="sr-only">Change language</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem
          onClick={() => changeLanguage('en')}
          disabled={currentLocale === 'en'}
        >
          English
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => changeLanguage('hi')}
          disabled={currentLocale === 'hi'}
        >
          हिन्दी (Hindi)
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => changeLanguage('mr')}
          disabled={currentLocale === 'mr'}
        >
          मराठी (Marathi)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
