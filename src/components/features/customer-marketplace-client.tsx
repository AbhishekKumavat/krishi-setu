'use client';

import { useState } from 'react';
import { Card, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import Link from 'next/link';
import { ShoppingBag, ArrowRight, Tag } from 'lucide-react';
import Image from 'next/image';

const MOCK_PRODUCTS = [
    {
        id: 'potato-jalgaon',
        name: 'Fresh Potatoes (Jalgaon Variety)',
        category: 'Vegetables',
        image: 'https://images.unsplash.com/photo-1518977676601-b53f82aba655?auto=format&fit=crop&q=80&w=400',
        startingPrice: 18, // per kg
    },
    {
        id: 'red-onion-nashik',
        name: 'Premium Red Onions (Nashik)',
        category: 'Vegetables',
        image: 'https://images.unsplash.com/photo-1618512496248-a07fe83aa8cb?auto=format&fit=crop&q=80&w=400',
        startingPrice: 22,
    },
    {
        id: 'wheat-sharbati',
        name: 'Sharbati Wheat (MP Origin)',
        category: 'Grains',
        image: 'https://images.unsplash.com/photo-1574323347407-f5e1ad6d020b?auto=format&fit=crop&q=80&w=400',
        startingPrice: 28,
    },
    {
        id: 'sugar-pure',
        name: 'Refined White Sugar',
        category: 'Staples',
        image: 'https://images.unsplash.com/photo-1622484211148-61d020d207ad?auto=format&fit=crop&q=80&w=400',
        startingPrice: 35,
    },
    {
        id: 'tomato-desi',
        name: 'Desi Tomatoes (Pesticide Free)',
        category: 'Vegetables',
        image: 'https://images.unsplash.com/photo-1592924357228-91a4daadcfea?auto=format&fit=crop&q=80&w=400',
        startingPrice: 31,
    },
    {
        id: 'banana-jalgaon',
        name: 'Jalgaon Grand Naine Bananas',
        category: 'Fruits',
        image: 'https://images.unsplash.com/photo-1603833665858-e61d17a86224?auto=format&fit=crop&q=80&w=400',
        startingPrice: 15,
    },
    {
        id: 'rice-basmati',
        name: 'Premium Basmati Rice',
        category: 'Grains',
        image: 'https://images.unsplash.com/photo-1586201375761-83865001e8ac?auto=format&fit=crop&q=80&w=400',
        startingPrice: 85,
    },
    {
        id: 'apple-kashmir',
        name: 'Kashmiri Apples',
        category: 'Fruits',
        image: 'https://images.unsplash.com/photo-1560806887-1e4cd0b6faa6?auto=format&fit=crop&q=80&w=400',
        startingPrice: 120,
    },
    {
        id: 'garlic-local',
        name: 'Organic Garlic',
        category: 'Vegetables',
        image: 'https://images.unsplash.com/photo-1615486511484-93afb91574cc?auto=format&fit=crop&q=80&w=400',
        startingPrice: 150,
    },
    {
        id: 'lentils-toor',
        name: 'Toor Dal (Unpolished)',
        category: 'Staples',
        image: 'https://images.unsplash.com/photo-1585996053862-22df65ba9eb5?auto=format&fit=crop&q=80&w=400',
        startingPrice: 140,
    },
    {
        id: 'mango-alphonso',
        name: 'Ratnagiri Alphonso Mango',
        category: 'Fruits',
        image: 'https://images.unsplash.com/photo-1553279768-865429fa0078?auto=format&fit=crop&q=80&w=400',
        startingPrice: 400,
    },
    {
        id: 'spinach-fresh',
        name: 'Fresh Spinach (Palak)',
        category: 'Vegetables',
        image: 'https://images.unsplash.com/photo-1576045057995-568f588f82fb?auto=format&fit=crop&q=80&w=400',
        startingPrice: 40,
    },
];

export function CustomerMarketplaceClient() {
    const [filter, setFilter] = useState('All');

    const filteredProducts = filter === 'All'
        ? MOCK_PRODUCTS
        : MOCK_PRODUCTS.filter(p => p.category === filter);

    return (
        <div className="space-y-6">

            {/* Category Toggles */}
            <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-hide py-1">
                {['All', 'Vegetables', 'Fruits', 'Grains', 'Staples'].map((cat) => (
                    <Button
                        key={cat}
                        variant={filter === cat ? 'default' : 'outline'}
                        className="rounded-full shadow-sm"
                        onClick={() => setFilter(cat)}
                    >
                        {cat}
                    </Button>
                ))}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-6">
                {filteredProducts.map((product) => (
                    <Link href={`/customer-marketplace/${product.id}`} key={product.id}>
                        <Card className="overflow-hidden hover:shadow-xl hover:-translate-y-1 transition-all duration-300 group cursor-pointer border-transparent bg-card group-hover:border-primary/20 h-full flex flex-col">
                            <div className="relative h-48 w-full bg-muted overflow-hidden">
                                <Image
                                    src={product.image}
                                    alt={product.name}
                                    fill
                                    className="object-cover transition-transform duration-500 group-hover:scale-105"
                                />
                                <div className="absolute top-2 left-2">
                                    <Badge className="bg-white/90 text-primary hover:bg-white border-none shadow-sm backdrop-blur-sm">
                                        {product.category}
                                    </Badge>
                                </div>
                            </div>
                            <CardContent className="p-4 flex flex-col flex-1">
                                <h3 className="font-headline font-bold text-lg mb-1 group-hover:text-primary transition-colors line-clamp-2">
                                    {product.name}
                                </h3>

                                <div className="mt-auto space-y-4">
                                    <div className="bg-primary/5 p-3 rounded-lg flex items-center gap-2 mt-4">
                                        <Tag className="h-4 w-4 text-primary shrink-0" />
                                        <div>
                                            <p className="text-[10px] uppercase font-bold text-primary tracking-wider">Prices Starting From</p>
                                            <p className="font-bold text-lg leading-tight mt-0.5 text-foreground">₹{product.startingPrice} <span className="text-muted-foreground text-xs font-normal">/kg</span></p>
                                        </div>
                                    </div>

                                    <Button className="w-full bg-emerald-600 hover:bg-emerald-700 shadow-md">
                                        <ShoppingBag className="mr-2 h-4 w-4" /> View Deals
                                        <ArrowRight className="ml-auto h-4 w-4 opacity-50 group-hover:translate-x-1 transition-transform" />
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    </Link>
                ))}
            </div>
        </div>
    );
}
