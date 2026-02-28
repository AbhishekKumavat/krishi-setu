import { Suspense } from 'react';
import { CustomerMarketplaceClient } from '@/components/features/customer-marketplace-client';

export default function CustomerMarketplacePage() {
    return (
        <div className="space-y-8">
            <div className="space-y-2">
                <h1 className="font-headline text-3xl md:text-4xl font-bold tracking-tight text-primary">
                    Customer Marketplace
                </h1>
                <p className="text-muted-foreground">
                    Buy fresh produce, vegetables, and grains directly from farmers at wholesale prices.
                </p>
            </div>

            <Suspense fallback={<div className="py-20 text-center animate-pulse">Loading amazing deals...</div>}>
                <CustomerMarketplaceClient />
            </Suspense>
        </div>
    );
}
