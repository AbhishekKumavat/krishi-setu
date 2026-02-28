import { Suspense } from 'react';
import { CustomerProductDetailClient } from '@/components/features/customer-product-detail-client';

export default function CustomerProductDetailPage() {
    return (
        <div className="space-y-8">
            <Suspense fallback={<div className="py-20 text-center animate-pulse">Loading supplier comparisons...</div>}>
                <CustomerProductDetailClient />
            </Suspense>
        </div>
    );
}
