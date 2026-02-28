'use client';

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Card, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from '../ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { ShieldCheck, Star, MapPin, Truck, Coins, Leaf, ArrowLeft, ArrowDown } from 'lucide-react';
import Image from 'next/image';
import { Label } from '../ui/label';
import { Input } from '../ui/input';

const MOCK_SELLERS = [
    { id: 's1', farmerName: 'Ramesh Patil', location: 'Nashik District', pricePerKg: 22, distanceKm: 4, trustScore: 4.8, isVerified: true },
    { id: 's2', farmerName: 'Sunil Shinde', location: 'Pimpalgaon Baswant', pricePerKg: 21.5, distanceKm: 12, trustScore: 4.5, isVerified: true },
    { id: 's3', farmerName: 'Kishore Agro', location: 'Malegaon', pricePerKg: 21, distanceKm: 45, trustScore: 4.2, isVerified: false },
    { id: 's4', farmerName: 'Vijay Farms', location: 'Ozar', pricePerKg: 22.5, distanceKm: 2, trustScore: 5.0, isVerified: true },
    { id: 's5', farmerName: 'Ganesh Mali', location: 'Lasalgaon', pricePerKg: 21.8, distanceKm: 18, trustScore: 4.4, isVerified: true },
];

export function CustomerProductDetailClient() {
    const params = useParams();
    const router = useRouter();
    const { toast } = useToast();
    const [checkoutModalOpen, setCheckoutModalOpen] = useState(false);
    const [selectedDeal, setSelectedDeal] = useState<any>(null);

    const [quantity, setQuantity] = useState('1');

    // Compute logistics math for sellers (metrics in kg)
    const processedSellers = MOCK_SELLERS.map(seller => {
        // approx delivery cost scaled for bulk per-kg basis (e.g. ₹0.07 per km)
        const transportCost = seller.distanceKm * 0.07;
        const finalPrice = seller.pricePerKg + transportCost;

        let deliveryEstimate = '2 Days';
        if (seller.distanceKm < 5) deliveryEstimate = 'Same Day Delivery';
        else if (seller.distanceKm <= 15) deliveryEstimate = '1-Day Delivery';

        return {
            ...seller,
            transportCost,
            finalPrice,
            deliveryEstimate
        }
    }).sort((a, b) => a.finalPrice - b.finalPrice); // Lowest final price first

    return (
        <div className="space-y-6 pb-20">

            {/* Back Header */}
            <button onClick={() => router.back()} className="text-muted-foreground hover:text-primary flex items-center font-medium transition-colors">
                <ArrowLeft className="h-4 w-4 mr-2" /> Back to Marketplace
            </button>

            {/* Main Product Banner */}
            <div className="bg-card border rounded-2xl overflow-hidden shadow-sm flex flex-col md:flex-row items-center p-6 gap-8 relative">
                <div className="md:w-1/3 aspect-video relative rounded-xl overflow-hidden shadow-inner border border-muted-foreground/10 bg-muted shrink-0 w-full">
                    {/* Fallback pattern if no image matching ID */}
                    <div className="absolute inset-0 bg-primary/10 flex items-center justify-center">
                        <Leaf className="h-20 w-20 text-primary/30" />
                    </div>
                    <Image
                        src="https://images.unsplash.com/photo-1618512496248-a07fe83aa8cb?auto=format&fit=crop&q=80&w=800"
                        alt="Product Header"
                        fill
                        className="object-cover relative z-10"
                    />
                </div>

                <div className="flex-1 w-full space-y-4">
                    <div className="space-y-1">
                        <Badge className="bg-amber-100 text-amber-800 hover:bg-amber-200 border-amber-200 shadow-none px-3">Live Comparison Active</Badge>
                        <h1 className="font-headline text-3xl font-bold tracking-tight">Premium Red Onions (Nashik)</h1>
                        <p className="text-muted-foreground flex items-center gap-2"><MapPin className="h-4 w-4" /> Delivered fresh to your location.</p>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t">
                        <div className="space-y-1">
                            <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Avg Market Price</p>
                            <p className="text-lg font-bold">₹23.50 <span className="text-sm font-normal text-muted-foreground">/ kg</span></p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-xs text-green-700 font-semibold uppercase tracking-wider">Lowest Deal Starts</p>
                            <p className="text-lg font-bold text-green-700">₹{processedSellers[0].finalPrice.toFixed(0)} <span className="text-sm font-normal opacity-70">inc. transport</span></p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Est. Fastest Delivery</p>
                            <p className="text-lg font-bold flex items-center gap-1.5"><Truck className="h-4 w-4 text-blue-500" /> Same Day</p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Verified Farmers</p>
                            <p className="text-lg font-bold flex items-center gap-1.5"><ShieldCheck className="h-4 w-4" /> {MOCK_SELLERS.length} Direct</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Comparison Deals Section */}
            <div className="space-y-4 pt-4">
                <div className="flex items-center gap-2 justify-between mb-6">
                    <h2 className="text-2xl font-headline font-semibold">Compare Deals</h2>
                    <div className="flex items-center text-xs text-muted-foreground bg-muted px-3 py-1.5 rounded-full font-medium">Sorted by Best Value <ArrowDown className="h-3 w-3 ml-1" /></div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {processedSellers.map((seller, index) => {
                        const isBestDeal = index === 0;

                        return (
                            <Card key={seller.id} className={`flex flex-col h-full overflow-hidden transition-all duration-300 shadow-sm hover:shadow-md border-2 ${isBestDeal ? 'border-amber-400 bg-amber-50/10' : 'border-transparent hover:border-border'}`}>
                                {isBestDeal && (
                                    <div className="bg-gradient-to-r from-amber-400 to-orange-500 text-white text-xs font-bold px-4 py-1.5 flex items-center justify-center uppercase tracking-widest shadow-sm shrink-0">
                                        Best Deal 🔥
                                    </div>
                                )}
                                <CardContent className="p-5 flex-1 flex flex-col space-y-4">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <h3 className="font-bold text-lg flex items-center gap-1">
                                                {seller.farmerName}
                                                {seller.isVerified && <ShieldCheck className="h-4 w-4 text-blue-500 shrink-0" />}
                                            </h3>
                                            <p className="text-sm text-muted-foreground flex items-center gap-1 mt-0.5"><MapPin className="h-3 w-3" /> {seller.location}</p>
                                        </div>
                                        <div className="flex items-center bg-green-100 text-green-800 px-2 py-0.5 rounded text-sm font-bold shadow-sm border border-green-200">
                                            <Star className="h-3 w-3 mr-1 fill-green-700" />
                                            {seller.trustScore.toFixed(1)}
                                        </div>
                                    </div>

                                    <div className="space-y-2.5 bg-muted/30 p-4 rounded-xl text-sm border flex-1">
                                        <div className="flex justify-between text-muted-foreground">
                                            <span>Farm Base Price</span>
                                            <span className="font-medium text-foreground">₹{seller.pricePerKg.toFixed(2)}/kg</span>
                                        </div>
                                        <div className="flex justify-between text-muted-foreground items-center">
                                            <span className="flex items-center gap-1.5"><Truck className="h-3.5 w-3.5" /> Transport ({seller.distanceKm}km)</span>
                                            <span className="font-medium text-foreground">+₹{seller.transportCost.toFixed(2)}</span>
                                        </div>
                                        <div className="h-px bg-border my-2 w-full"></div>
                                        <div className="flex justify-between font-bold text-lg text-emerald-700 py-1">
                                            <span>Final Delivered Price</span>
                                            <span>₹{seller.finalPrice.toFixed(2)}</span>
                                        </div>
                                    </div>

                                    <div className="flex items-center justify-between mt-auto pt-2">
                                        <p className="text-xs font-semibold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-full border border-blue-100">{seller.deliveryEstimate}</p>
                                        <Button size="sm" className="bg-[#16a34a] hover:bg-green-700 font-bold px-6 shadow-md" onClick={() => {
                                            setSelectedDeal(seller);
                                            setCheckoutModalOpen(true);
                                        }}>
                                            Buy Now
                                        </Button>
                                    </div>
                                </CardContent>
                            </Card>
                        )
                    })}
                </div>
            </div>

            {/* CHECKOUT MODAL */}
            <Dialog open={checkoutModalOpen} onOpenChange={setCheckoutModalOpen}>
                <DialogContent className="sm:max-w-[425px]">
                    <DialogHeader className="border-b pb-4 mb-4">
                        <DialogTitle className="text-xl">Express Checkout</DialogTitle>
                        <DialogDescription>
                            Complete your order with {selectedDeal?.farmerName}.
                        </DialogDescription>
                    </DialogHeader>

                    {selectedDeal && (
                        <div className="space-y-5 py-2">
                            <div className="flex justify-between items-center bg-green-50 p-4 rounded-xl border border-green-100 shadow-inner">
                                <div className="space-y-1">
                                    <p className="text-xs text-green-800 uppercase font-black tracking-wider">Unit Price</p>
                                    <p className="font-bold text-green-900 text-xl font-headline">₹{selectedDeal.finalPrice.toFixed(0)}</p>
                                </div>
                                <div className="text-right space-y-1">
                                    <p className="text-xs text-green-800 uppercase font-black tracking-wider">Grand Total</p>
                                    <p className="font-bold text-green-900 text-2xl font-headline">₹{(selectedDeal.finalPrice * parseInt(quantity || '1')).toFixed(0)}</p>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <Label htmlFor="qty" className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Quantity (kg)</Label>
                                    <Input
                                        id="qty"
                                        type="number"
                                        value={quantity}
                                        onChange={(e) => setQuantity(e.target.value)}
                                        min="1"
                                        className="font-bold text-lg"
                                    />
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="address" className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Delivery Address</Label>
                                    <textarea
                                        id="address"
                                        className="w-full flex min-h-[80px] rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 resize-none font-medium"
                                        placeholder="Enter your full street address..."
                                    ></textarea>
                                </div>

                                <div className="space-y-2">
                                    <Label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Payment Method</Label>
                                    <div className="flex gap-2">
                                        <div className="flex-1 bg-primary/10 border-2 border-primary text-primary font-bold rounded-lg p-3 text-center cursor-pointer text-sm shadow-sm transition-transform active:scale-95">
                                            Cash on Delivery
                                        </div>
                                        <div className="flex-1 border-2 border-border text-muted-foreground font-medium rounded-lg p-3 text-center cursor-pointer text-sm hover:border-primary/50 transition-colors">
                                            UPI Payment
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    <DialogFooter className="border-t pt-4 mt-2">
                        <Button
                            variant="outline"
                            onClick={() => setCheckoutModalOpen(false)}
                            className="w-full sm:w-auto"
                        >
                            Cancel
                        </Button>
                        <Button
                            className="w-full bg-[#16a34a] hover:bg-green-700 font-bold shadow-md shadow-green-600/20"
                            onClick={() => {
                                toast({
                                    title: "Order Placed Successfully! 🎉",
                                    description: `Your order for ${quantity} kg has been sent to ${selectedDeal?.farmerName}.`,
                                });
                                setCheckoutModalOpen(false);
                            }}
                        >
                            Confirm Order
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
