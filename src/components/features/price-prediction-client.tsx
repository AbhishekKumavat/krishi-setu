'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { format } from 'date-fns';
import { CalendarIcon, Loader2, TrendingUp } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { predictPrice } from '@/app/actions/predict-price';
import type { PredictCropPriceOutput } from '@/ai/flows/crop-price-prediction';
import { useToast } from '@/hooks/use-toast';
import { Badge } from '../ui/badge';

const formSchema = z.object({
  region: z.string().min(1, 'Region is required.'),
  crop: z.string().min(1, 'Crop is required.'),
  variety: z.string().optional().default('FAQ'),
  date: z.date().optional().default(new Date()),
  quantity: z.coerce.number().min(1).default(1000),
});

export function PricePredictionClient() {
  const [result, setResult] = useState<PredictCropPriceOutput | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      region: '',
      crop: '',
      variety: 'FAQ',
      date: new Date(),
      quantity: 1000,
    }
  });

  const currentQuantityKg = form.watch('quantity') || 1000;

  // Current Math
  const currentQuintals = currentQuantityKg / 100;
  const sellTodayRevenue = result ? result.currentMandiPrice * currentQuintals : 0;

  // Future Math
  const futureQuintals = currentQuintals;
  const futurePrice = result ? (result.predictedData?.[3]?.price || result.predictedPriceMax) : 0;
  const sellFutureRevenue = futurePrice * futureQuintals;

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true);
    setResult(null);
    const { success, data, error } = await predictPrice(values);
    setIsLoading(false);

    if (success && data) {
      setResult(data);
    } else {
      toast({
        variant: 'destructive',
        title: 'Prediction Failed',
        description: error || 'An unexpected error occurred.',
      });
    }
  }

  return (
    <div className="space-y-8 w-full max-w-[1600px] mx-auto">
      <Card className="border-green-100 shadow-sm border overflow-hidden rounded-xl">
        <div className="bg-[#f0fdf4] p-4 border-b border-green-100 flex items-center gap-2">
          <TrendingUp className="text-green-600 h-5 w-5" />
          <h3 className="font-headline font-bold text-green-800 tracking-wide text-sm">Profit Analyzer</h3>
        </div>
        <CardContent className="p-6 bg-white">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="grid grid-cols-1 md:grid-cols-4 gap-6 items-end">
              <FormField
                control={form.control}
                name="crop"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Select Crop</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Wheat (गेहूं)" className="bg-muted/30 border-muted" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="region"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Select Mandi</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Nashik Mandi (नाशिक)" className="bg-muted/30 border-muted" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="quantity"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Quantity (KG)</FormLabel>
                    <FormControl>
                      <Input type="number" placeholder="1000" className="bg-muted/30 border-muted" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />
              <Button type="submit" disabled={isLoading} className="w-full bg-[#16a34a] hover:bg-green-700 text-white font-semibold">
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <TrendingUp className="mr-2 h-4 w-4" />
                )}
                Analyze Profit
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
      <div className="flex items-center justify-center">
        {isLoading && (
          <div className="flex flex-col items-center gap-4 text-center">
            <Loader2 className="h-12 w-12 animate-spin text-primary" />
            <h2 className="font-headline text-2xl font-semibold">
              Predicting Price...
            </h2>
            <p className="text-muted-foreground">
              Our AI is analyzing market data. Please wait a moment.
            </p>
          </div>
        )}
        {!isLoading && !result && (
          <Card className="w-full h-full flex flex-col items-center justify-center bg-muted/50 border-dashed">
            <CardContent className="text-center p-6">
              <TrendingUp className="mx-auto h-12 w-12 text-muted-foreground" />
              <h3 className="mt-4 text-lg font-medium font-headline">Awaiting Prediction</h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Your price prediction will appear here.
              </p>
            </CardContent>
          </Card>
        )}
        {result && (
          <div className="space-y-6 animate-in fade-in-50">
            {/* Live Data Badge Alert */}
            {result.isLiveMandiData && (
              <div className="bg-green-50 border-l-4 border-green-500 p-4 rounded-r-lg flex items-center gap-3">
                <span className="flex h-3 w-3 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
                <p className="text-sm text-green-800 font-medium">Model is synced with live data.gov.in Mandi API (Agmarknet)</p>
              </div>
            )}

            {/* Price Timeline Chart */}
            {(result.historicalData?.length > 0 || result.predictedData?.length > 0) && (
              <div className="border rounded-xl p-6 bg-white shadow-sm">
                <h4 className="font-headline font-semibold text-lg flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                  <div>
                    <span className="block text-xl font-bold">Price Trend Analysis</span>
                    <span className="text-sm font-normal text-muted-foreground">Historical vs AI-Predicted Prices (₹/quintal)</span>
                  </div>
                  <span className="text-sm font-medium text-muted-foreground flex gap-4">
                    <span className="flex items-center gap-2"><span className="w-4 h-1 rounded-full bg-[#3b82f6]"></span> Historical</span>
                    <span className="flex items-center gap-2"><span className="w-4 h-1 rounded-full border border-dashed border-[#f97316]"></span> Predicted</span>
                  </span>
                </h4>
                <div className="h-[500px] w-full mt-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart
                      data={[
                        ...result.historicalData.map(d => ({ date: d.date, historical: d.price, predicted: null })),
                        { date: "Today", historical: result.currentMandiPrice, predicted: result.currentMandiPrice },
                        ...result.predictedData.map(d => ({ date: d.date, historical: null, predicted: d.price }))
                      ]}
                      margin={{ top: 20, right: 20, left: 0, bottom: 20 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
                      <XAxis
                        dataKey="date"
                        stroke="#6b7280"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tickMargin={12}
                      />
                      <YAxis
                        tickFormatter={(value) => `₹${value}`}
                        stroke="#6b7280"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tickMargin={12}
                      />
                      <Tooltip
                        formatter={(value: number) => [`₹${value}`, 'Price']}
                        contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)' }}
                        labelStyle={{ color: '#374151', fontWeight: 'bold', marginBottom: '4px' }}
                      />
                      <Line
                        type="monotone"
                        dataKey="historical"
                        stroke="#3b82f6"
                        strokeWidth={3}
                        dot={{ r: 4, fill: '#3b82f6', strokeWidth: 0 }}
                        activeDot={{ r: 6, strokeWidth: 0 }}
                        connectNulls
                      />
                      <Line
                        type="monotone"
                        dataKey="predicted"
                        stroke="#f97316"
                        strokeWidth={3}
                        strokeDasharray="6 6"
                        dot={{ r: 4, fill: '#f97316', strokeWidth: 0 }}
                        activeDot={{ r: 6, strokeWidth: 0 }}
                        connectNulls
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Actionable Prediction Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
              {/* Sell Today Card */}
              <div className="rounded-xl border border-green-100 bg-[#f8faf7] p-6 shadow-sm relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1.5 h-full bg-green-500"></div>
                <div className="flex justify-between items-start mb-6">
                  <h3 className="font-headline font-bold text-green-700 tracking-wider text-sm">SELL TODAY</h3>
                  <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">Current Rate</Badge>
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-green-800/70 mb-1">Total Revenue</p>
                    <p className="text-4xl font-headline font-bold text-foreground">
                      ₹{sellTodayRevenue.toLocaleString('en-IN', { maximumFractionDigits: 0 })}
                    </p>
                  </div>
                </div>
              </div>

              {/* Sell in 4 Days Card */}
              <div className="rounded-xl border border-orange-100 bg-[#fffaf5] p-6 shadow-sm relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1.5 h-full bg-orange-400"></div>
                <div className="flex justify-between items-start mb-6">
                  <h3 className="font-headline font-bold text-orange-600 tracking-wider text-sm">SELL IN 4 DAYS</h3>
                  <Badge variant="outline" className="bg-orange-50 text-orange-700 border-orange-200">Predicted Rate</Badge>
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-orange-800/70 mb-1">Total Revenue</p>
                    <div className="flex items-baseline gap-3">
                      <p className="text-4xl font-headline font-bold text-foreground">
                        ₹{sellFutureRevenue.toLocaleString('en-IN', { maximumFractionDigits: 0 })}
                      </p>
                      <span className={cn("text-sm font-medium", result.percentageChange >= 0 ? "text-green-600" : "text-destructive")}>
                        {result.percentageChange >= 0 ? '▲ +' : '▼ '}{result.percentageChange}% return
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex flex-col md:flex-row justify-between items-center bg-muted/30 p-4 rounded-xl mt-6">
              <div>
                <h4 className="font-headline font-semibold text-sm text-muted-foreground mb-2 md:mb-0">
                  Top Market Factors
                </h4>
                <div className="flex flex-wrap gap-2 mt-1">
                  {result.factors.map((factor) => (
                    <Badge key={factor} variant="secondary" className="bg-background">
                      {factor}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="text-right mt-4 md:mt-0">
                <p className="text-sm font-medium text-muted-foreground">AI Confidence</p>
                <p className="font-headline text-2xl font-bold text-foreground">
                  {(result.confidence * 100).toFixed(0)}%
                </p>
              </div>
            </div>

            <div className="text-center pt-8 pb-4">
              <p className="text-xs text-muted-foreground">
                Based on historical mandi price trends (2020–2025). Models update dynamically on available live data.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
