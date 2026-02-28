'use client';

import { useState, useEffect, useRef } from 'react';
import { Button } from '../ui/button';
import { Card, CardContent } from '../ui/card';
import { Badge } from '../ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { MapPin, Navigation, Star, ShieldCheck, Phone, CheckCircle, Truck, TrendingUp, Info, Loader2 } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';

// ─── TYPES ─────────────────────────────────────────────────────────────
type Retailer = {
    id: string;
    name: string;
    type: string;
    lat: number;
    lon: number;
    offeredPrice: number; // per quintal
    trustScore: number;
    isVerified: boolean;
    image: string;
    address: string;
    phone: string;
    paymentTerms: string;
};

// ─── STATIC DATASET (Jalgaon focus) ──────────────────────────────────
const MOCK_RETAILERS: Retailer[] = [
    {
        id: '1',
        name: "Jalgaon APMC Market Yard",
        type: "Wholesale Mandi",
        address: "Near Ajanta Chowk, MH SH 186, Jalgaon, Maharashtra",
        phone: "+91 257 222XXXX",
        lat: 21.0077,
        lon: 75.5626,
        trustScore: 4.6,
        isVerified: true,
        offeredPrice: 2750,
        image: 'https://images.unsplash.com/photo-1542838132-92c53300491e?auto=format&fit=crop&q=80&w=200',
        paymentTerms: 'Immediate Cash / UPI',
    },
    {
        id: '2',
        name: "M/s Hirman Bansi Mali And Sons",
        type: "Vegetable Wholesale Market",
        address: "Sabji Mandi, Ajanta Road, Jalgaon",
        phone: "+91 98909XXXXX",
        lat: 21.0049,
        lon: 75.5668,
        trustScore: 4.4,
        isVerified: true,
        offeredPrice: 2680,
        image: 'https://images.unsplash.com/photo-1581578731548-c64695cc6952?auto=format&fit=crop&q=80&w=200',
        paymentTerms: 'Bank Transfer (2 Days)',
    },
    {
        id: '3',
        name: "Nandini Trading Co.",
        type: "Vegetable Wholesaler",
        address: "New Sabji Mandi, Sureshdada Jain Market, Jalgaon",
        phone: "+91 94222XXXXX",
        lat: 21.0062,
        lon: 75.5685,
        trustScore: 4.2,
        isVerified: true,
        offeredPrice: 2720,
        image: 'https://images.unsplash.com/photo-1488459716781-31db52582fe9?auto=format&fit=crop&q=80&w=200',
        paymentTerms: 'Immediate Cash',
    },
    {
        id: '4',
        name: "Mo. Younis S. Bismilla And Co.",
        type: "Wholesale Vegetable Dealer",
        address: "Sabji Mandi, Ajanta Road, Jalgaon",
        phone: "+91 75888XXXXX",
        lat: 21.0038,
        lon: 75.5659,
        trustScore: 4.5,
        isVerified: true,
        offeredPrice: 2800,
        image: 'https://images.unsplash.com/photo-1595859702816-43c3d52d9b62?auto=format&fit=crop&q=80&w=200',
        paymentTerms: 'UPI / Bank Transfer',
    },
    {
        id: '5',
        name: "K.P. Traders",
        type: "Fruits & Vegetable Wholesaler",
        address: "Ajanta Road, Sabji Mandi, Jalgaon",
        phone: "+91 98230XXXXX",
        lat: 21.0053,
        lon: 75.5672,
        trustScore: 4.3,
        isVerified: true,
        offeredPrice: 2650,
        image: 'https://images.unsplash.com/photo-1605371924599-2d0365da1ae0?auto=format&fit=crop&q=80&w=200',
        paymentTerms: 'Cash',
    }
];

// ─── LOGIC ───────────────────────────────────────────────────────────
function deg2rad(deg: number) {
    return deg * (Math.PI / 180);
}

function getDistanceFromLatLonInKm(lat1: number, lon1: number, lat2: number, lon2: number) {
    const R = 6371;
    const dLat = deg2rad(lat2 - lat1);
    const dLon = deg2rad(lon2 - lon1);
    const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

export function MarketplaceClient() {
    const [userLoc, setUserLoc] = useState<{ lat: number, lon: number } | null>(null);
    const [detectingLoc, setDetectingLoc] = useState(false);
    const [retailersList, setRetailersList] = useState<any[]>([]); // Array of processed retailers
    const [sortBy, setSortBy] = useState('netProfit'); // netProfit | distance | trustScore
    const [selectedRetailer, setSelectedRetailer] = useState<any | null>(null);
    const [leafletLoaded, setLeafletLoaded] = useState(false);

    const mapContainerRef = useRef<HTMLDivElement>(null);
    const mapInstanceRef = useRef<any>(null);
    const userMarkerRef = useRef<any>(null);
    const retailerMarkersRef = useRef<any[]>([]);

    const { toast } = useToast();

    // Inject Leaflet library strictly without NPM to avoid environment crashes
    useEffect(() => {
        if (typeof window !== 'undefined' && !document.getElementById('leaflet-css')) {
            const link = document.createElement('link');
            link.id = 'leaflet-css';
            link.rel = 'stylesheet';
            link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
            document.head.appendChild(link);

            const script = document.createElement('script');
            script.id = 'leaflet-js';
            script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
            script.onload = () => setLeafletLoaded(true);
            document.head.appendChild(script);
        } else {
            if ((window as any).L) setLeafletLoaded(true);
        }

        // Fallback load of all mocked retailers immediately
        calculateRetailersAndSort(null, 'netProfit');
    }, []);

    // Initialize Map Once
    useEffect(() => {
        if (leafletLoaded && mapContainerRef.current && !mapInstanceRef.current) {
            const L = (window as any).L;
            // Default to Maharashtra bounds
            mapInstanceRef.current = L.map(mapContainerRef.current).setView([19.75, 75.71], 6);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap contributors',
                maxZoom: 18,
            }).addTo(mapInstanceRef.current);

            renderMarkers(userLoc, MOCK_RETAILERS);
        }
    }, [leafletLoaded]);

    // Re-render markers if map already exists
    useEffect(() => {
        if (mapInstanceRef.current && leafletLoaded) {
            renderMarkers(userLoc, MOCK_RETAILERS);
        }
    }, [userLoc, leafletLoaded]);

    function renderMarkers(loc: { lat: number, lon: number } | null, retailers: Retailer[]) {
        const L = (window as any).L;
        const map = mapInstanceRef.current;
        if (!map || !L) return;

        // Clear old markers
        if (userMarkerRef.current) map.removeLayer(userMarkerRef.current);
        retailerMarkersRef.current.forEach(m => map.removeLayer(m));
        retailerMarkersRef.current = [];

        // Add user marker
        if (loc) {
            const userIcon = L.icon({
                iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png',
                shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/images/marker-shadow.png',
                iconSize: [25, 41],
                iconAnchor: [12, 41],
                popupAnchor: [1, -34],
                shadowSize: [41, 41]
            });

            userMarkerRef.current = L.marker([loc.lat, loc.lon], { icon: userIcon }).addTo(map)
                .bindPopup('<b>You are here</b><br/>Farmer Location').openPopup();

            map.setView([loc.lat, loc.lon], 8);
        }

        // Add retailer markers
        retailers.forEach(r => {
            const marker = L.marker([r.lat, r.lon]).addTo(map)
                .bindPopup(`<b>${r.name}</b><br/>₹${r.offeredPrice}/quintal`);
            retailerMarkersRef.current.push(marker);

            // Basic click handler for markers
            marker.on('click', () => {
                const found = retailersList.find(rx => rx.id === r.id) || r;
                setSelectedRetailer(found);
            });
        });
    }

    const handleDetectLocation = () => {
        if (!navigator.geolocation) {
            toast({ title: 'Geolocation Not Supported', description: 'Your browser does not support geolocation.', variant: 'destructive' });
            return;
        }
        setDetectingLoc(true);
        navigator.geolocation.getCurrentPosition(
            (pos) => {
                const uLat = pos.coords.latitude;
                const uLon = pos.coords.longitude;
                setUserLoc({ lat: uLat, lon: uLon });
                calculateRetailersAndSort({ lat: uLat, lon: uLon }, sortBy);
                setDetectingLoc(false);
            },
            (error) => {
                setDetectingLoc(false);
                toast({ title: 'Location Error', description: error.message || 'Could not fetch your location.', variant: 'destructive' });
            }
        );
    };

    const calculateRetailersAndSort = (loc: { lat: number, lon: number } | null, sortKey: string) => {
        let processed = MOCK_RETAILERS.map(r => {
            let dist = 0;
            let transCost = 0;

            if (loc) {
                dist = getDistanceFromLatLonInKm(loc.lat, loc.lon, r.lat, r.lon);
                // Standard cargo rate: ~₹8 per quintal per KM
                transCost = dist * 8;
            } else {
                // Fallbacks if no location detected
                dist = 9999;
                transCost = 0;
            }
            return {
                ...r,
                distance: dist,
                transportCost: transCost,
                netProfit: r.offeredPrice - transCost
            };
        });

        processed.sort((a, b) => {
            if (sortKey === 'netProfit') return b.netProfit - a.netProfit;
            if (sortKey === 'distance') return a.distance - b.distance;
            if (sortKey === 'trustScore') return b.trustScore - a.trustScore;
            return 0;
        });

        setRetailersList(processed);
    };

    // Re-sort effect
    useEffect(() => {
        if (retailersList.length > 0) {
            calculateRetailersAndSort(userLoc, sortBy);
        }
    }, [sortBy]);


    return (
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row items-center gap-4 bg-primary/10 p-4 rounded-xl border border-primary/20">
                <MapPin className="h-8 w-8 text-primary" />
                <div className="flex-1">
                    <h2 className="font-headline font-bold text-lg text-primary">Discover Buyers & Retailers</h2>
                    <p className="text-sm text-muted-foreground">Detect your location to find the nearest and most profitable buyers for your crop using live OpenStreetMap tracking.</p>
                </div>
                <Button onClick={handleDetectLocation} disabled={detectingLoc} className="w-full md:w-auto">
                    {detectingLoc ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Navigation className="mr-2 h-4 w-4" />}
                    Detect My Location
                </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* LEFT COLUMN: Retailer List */}
                <div className="lg:col-span-1 border rounded-xl bg-card overflow-hidden shadow-sm flex flex-col h-[700px]">
                    <div className="p-4 border-b bg-muted/30 flex justify-between items-center">
                        <h3 className="font-bold font-headline">Nearby Retailers</h3>
                        <Select value={sortBy} onValueChange={setSortBy}>
                            <SelectTrigger className="w-[140px] text-xs h-8">
                                <SelectValue placeholder="Sort by" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="netProfit">Highest Profit</SelectItem>
                                <SelectItem value="distance">Shortest Distance</SelectItem>
                                <SelectItem value="trustScore">Highest Rating</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {retailersList.map((ret, index) => (
                            <Card
                                key={ret.id}
                                className="cursor-pointer hover:border-primary/50 transition-colors shadow-sm"
                                onClick={() => setSelectedRetailer(ret)}
                            >
                                <CardContent className="p-4">
                                    <div className="flex gap-3 mb-3">
                                        <img src={ret.image} alt={ret.name} className="w-12 h-12 rounded-lg object-cover bg-muted" />
                                        <div>
                                            <h4 className="font-bold text-sm tracking-tight flex items-center gap-1 flex-wrap">
                                                {ret.name}
                                                {ret.isVerified && <ShieldCheck className="h-3.5 w-3.5 text-blue-500" />}
                                                {index === 0 && <Badge variant="default" className="bg-primary/20 text-primary border-primary/30 text-[10px] h-4 ml-1">AI Recommended</Badge>}
                                            </h4>
                                            <p className="text-xs text-muted-foreground flex gap-2 mt-0.5">
                                                <span className="bg-primary/10 text-primary px-1.5 py-0.5 rounded text-[10px] uppercase font-bold tracking-widest">{ret.type}</span>
                                                <span className="flex items-center text-amber-600"><Star className="h-3 w-3 mr-1 fill-amber-500" />{ret.trustScore}</span>
                                            </p>
                                        </div>
                                    </div>

                                    <div className="space-y-2 text-xs">
                                        <div className="flex justify-between items-center bg-muted/40 px-2 py-1.5 rounded">
                                            <span className="text-muted-foreground">Offered Price</span>
                                            <span className="font-semibold">₹{ret.offeredPrice}/q</span>
                                        </div>
                                        <div className="flex justify-between items-center bg-muted/40 px-2 py-1.5 rounded">
                                            <span className="text-muted-foreground flex items-center gap-1"><Truck className="h-3 w-3" /> Transport {userLoc ? `(${ret.distance.toFixed(0)}km)` : ''}</span>
                                            <span className="text-destructive font-medium">{userLoc ? `-₹${ret.transportCost.toFixed(0)}/q` : 'N/A'}</span>
                                        </div>
                                        <div className="flex justify-between items-center bg-green-50 text-green-800 px-2 py-1.5 rounded border border-green-100 font-bold">
                                            <span className="flex items-center gap-1"><TrendingUp className="h-3 w-3" /> Net Profit</span>
                                            <span className="text-sm">₹{userLoc ? ret.netProfit.toFixed(0) : ret.offeredPrice}/q</span>
                                        </div>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            className="w-full mt-2"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                const url = userLoc
                                                    ? `https://www.google.com/maps/dir/?api=1&origin=${userLoc.lat},${userLoc.lon}&destination=${ret.lat},${ret.lon}`
                                                    : `https://www.google.com/maps/dir/?api=1&destination=${ret.lat},${ret.lon}`;
                                                window.open(url, '_blank');
                                            }}
                                        >
                                            <Navigation className="h-3 w-3 mr-2" /> Get Directions
                                        </Button>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </div>

                {/* RIGHT COLUMN: Leaflet Map */}
                <div className="lg:col-span-2 border rounded-xl overflow-hidden shadow-sm h-[700px] relative z-0">
                    <div ref={mapContainerRef} className="absolute inset-0 z-0 border-0 outline-none"></div>
                    {!leafletLoaded && (
                        <div className="absolute inset-0 bg-background/80 flex items-center justify-center z-10 backdrop-blur-sm">
                            <Loader2 className="h-8 w-8 animate-spin text-primary" />
                        </div>
                    )}
                </div>
            </div>

            {/* RETAILER DETAILS MODAL */}
            <Dialog open={!!selectedRetailer} onOpenChange={(open) => !open && setSelectedRetailer(null)}>
                <DialogContent className="sm:max-w-md z-50">
                    {selectedRetailer && (
                        <>
                            <DialogHeader>
                                <div className="flex items-start gap-4 mb-2">
                                    <img src={selectedRetailer.image} alt={selectedRetailer.name} className="w-16 h-16 rounded-lg object-cover shadow-sm bg-muted" />
                                    <div>
                                        <DialogTitle className="flex items-center gap-2">
                                            {selectedRetailer.name}
                                            {selectedRetailer.isVerified && <ShieldCheck className="h-4 w-4 text-blue-500" />}
                                        </DialogTitle>
                                        <div className="mt-1 flex items-center gap-2">
                                            <DialogDescription className="sr-only">
                                                Retailer ({selectedRetailer.type}) with a trust score of {selectedRetailer.trustScore}.
                                            </DialogDescription>
                                            <Badge variant="outline">{selectedRetailer.type}</Badge>
                                            <span className="flex items-center text-amber-600 text-sm font-medium"><Star className="h-3.5 w-3.5 mr-1 fill-amber-500" />{selectedRetailer.trustScore}</span>
                                        </div>
                                    </div>
                                </div>
                            </DialogHeader>

                            <div className="space-y-4 py-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="bg-muted/40 p-3 rounded-xl border relative overflow-hidden">
                                        <div className="absolute top-0 left-0 w-1 h-full bg-primary/50"></div>
                                        <p className="text-xs text-muted-foreground mb-1">Offered Price</p>
                                        <p className="font-headline font-bold text-lg">₹{selectedRetailer.offeredPrice}<span className="text-xs font-normal text-muted-foreground">/q</span></p>
                                    </div>
                                    <div className="bg-green-50 p-3 rounded-xl border border-green-100 relative overflow-hidden">
                                        <div className="absolute top-0 left-0 w-1 h-full bg-green-500"></div>
                                        <p className="text-xs text-green-800/70 mb-1">Est. Net Profit</p>
                                        <p className="font-headline font-bold text-lg text-green-700">₹{userLoc ? selectedRetailer.netProfit.toFixed(0) : selectedRetailer.offeredPrice}<span className="text-xs font-normal opacity-70">/q</span></p>
                                    </div>
                                </div>

                                <div className="bg-muted p-3 rounded-xl space-y-3 mt-4 text-sm">
                                    <div className="flex items-start gap-3">
                                        <MapPin className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                                        <p className="text-muted-foreground">{selectedRetailer.address}</p>
                                    </div>
                                    <div className="w-full h-32 mt-2 rounded-lg overflow-hidden border">
                                        <iframe
                                            width="100%"
                                            height="100%"
                                            frameBorder="0"
                                            scrolling="no"
                                            src={`https://www.openstreetmap.org/export/embed.html?bbox=${selectedRetailer.lon - 0.01},${selectedRetailer.lat - 0.01},${selectedRetailer.lon + 0.01},${selectedRetailer.lat + 0.01}&layer=mapnik&marker=${selectedRetailer.lat},${selectedRetailer.lon}`}
                                        ></iframe>
                                    </div>
                                    <div className="flex items-start gap-3 mt-3">
                                        <Truck className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                                        <p className="text-muted-foreground">
                                            {userLoc ? `${selectedRetailer.distance.toFixed(1)} km away (Est. ₹${selectedRetailer.transportCost.toFixed(0)}/quintal transport)` : 'Distance unknown (Locate me to calculate)'}
                                        </p>
                                    </div>
                                    <div className="flex justify-between items-center border-t pt-3 mt-3">
                                        <div className="flex items-center gap-2">
                                            <Info className="h-4 w-4 text-muted-foreground" />
                                            <span className="text-xs text-muted-foreground">Payment: {selectedRetailer.paymentTerms}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row gap-3 pt-2">
                                <Button className="w-full bg-[#16a34a] hover:bg-green-700" onClick={() => window.open(`tel:${selectedRetailer.phone}`)}>
                                    <Phone className="mr-2 h-4 w-4" /> Call Buyer
                                </Button>
                                <Button variant="outline" className="w-full" onClick={() => {
                                    toast({ title: "Opening Messages", description: `Starting conversation with ${selectedRetailer.name}` });
                                }}>
                                    Send Message
                                </Button>
                            </div>
                            <Button
                                variant="secondary"
                                className="w-full mt-2 bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200"
                                onClick={() => {
                                    const url = userLoc
                                        ? `https://www.google.com/maps/dir/?api=1&origin=${userLoc.lat},${userLoc.lon}&destination=${selectedRetailer.lat},${selectedRetailer.lon}`
                                        : `https://www.google.com/maps/dir/?api=1&destination=${selectedRetailer.lat},${selectedRetailer.lon}`;
                                    window.open(url, '_blank');
                                }}
                            >
                                <Navigation className="mr-2 h-4 w-4" /> Get Directions
                            </Button>
                        </>
                    )}
                </DialogContent>
            </Dialog>
        </div>
    );
}
