import { MarketplaceClient } from '@/components/features/marketplace-client';
import { Suspense } from 'react';

export default function MarketplacePage() {
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="font-headline text-3xl md:text-4xl font-bold tracking-tight">
          Buyer Network
        </h1>
        <p className="text-muted-foreground">
          Locate verified wholesale buyers and exporters for your produce directly on the map.
        </p>
      </div>
      <Suspense fallback={<p>Loading marketplace...</p>}>
        <MarketplaceClient />
      </Suspense>
    </div>
  );
}
