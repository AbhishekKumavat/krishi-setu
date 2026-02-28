'use server';

const DATA_GOV_API_KEY = '579b464db66ec23bdd000001dfe40d65373a40b972eaf6d03322ffd4';
const MANDI_RESOURCE_ID = '9ef84268-d588-465a-a308-a864a43d0070';

async function fetchLiveMandiPrice(crop: string): Promise<number | null> {
  try {
    // Attempt 1: Search by `commodity` filter
    const url = `https://api.data.gov.in/resource/${MANDI_RESOURCE_ID}?api-key=${DATA_GOV_API_KEY}&format=json&limit=15&filters[commodity]=${encodeURIComponent(crop)}`;
    console.log('[Mandi API] Fetching from:', url);

    // Disable cache completely to ensure we get fresh results for debugging
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) {
      console.warn(`[Mandi API] HTTP Error: ${res.status}`);
    } else {
      const data = await res.json();
      if (data && data.records && data.records.length > 0) {
        for (const record of data.records) {
          const num = parseInt(record.modal_price);
          if (!isNaN(num) && num > 0) {
            console.log(`[Mandi API] Found live price for ${crop}: ₹${num}`);
            return num;
          }
        }
      }
    }

    // Attempt 2: Search with capitalized crop name just in case
    const capitalizedCrop = crop.charAt(0).toUpperCase() + crop.slice(1).toLowerCase();
    const urlCap = `https://api.data.gov.in/resource/${MANDI_RESOURCE_ID}?api-key=${DATA_GOV_API_KEY}&format=json&limit=15&filters[commodity]=${encodeURIComponent(capitalizedCrop)}`;
    console.log('[Mandi API] Fallback Fetching from:', urlCap);

    const resCap = await fetch(urlCap, { cache: 'no-store' });
    if (!resCap.ok) {
      console.warn(`[Mandi API] Fallback HTTP Error: ${resCap.status}`);
    } else {
      const searchData = await resCap.json();
      if (searchData && searchData.records && searchData.records.length > 0) {
        for (const record of searchData.records) {
          const num = parseInt(record.modal_price);
          if (!isNaN(num) && num > 0) {
            console.log(`[Mandi API] Found live price for ${capitalizedCrop} (via search): ₹${num}`);
            return num;
          }
        }
      }
    }
  } catch (error) {
    console.warn('[Mandi API] Failed to fetch live price:', error);
  }
  console.log(`[Mandi API] No live price found for ${crop}, falling back.`);
  return null;
}

export type PredictCropPriceInput = {
  region: string;
  crop: string;
  variety: string;
  date: string;
};

export type PriceDataPoint = {
  date: string;
  price: number;
};

export type PredictCropPriceOutput = {
  currentMandiPrice: number;
  predictedPriceMin: number;
  predictedPriceMax: number;
  percentageChange: number;
  confidence: number;
  recommendedListingPrice: number;
  factors: string[];
  historicalData: PriceDataPoint[];
  predictedData: PriceDataPoint[];
  isLiveMandiData: boolean;
};

export async function predictCropPrice(
  input: PredictCropPriceInput
): Promise<PredictCropPriceOutput> {
  const apiKey = process.env.GEMINI_API_KEY;
  console.log('[Price Prediction] Starting for:', input.crop, input.region);

  if (!apiKey) {
    return getFallbackPrediction(input);
  }

  const liveMandiPrice = await fetchLiveMandiPrice(input.crop);
  const liveContextText = liveMandiPrice
    ? `\n- LIVE GOVT MANDI DATA: The *actual* current modal price for ${input.crop} on the Agmarknet API right now is precisely ₹${liveMandiPrice} per quintal. You MUST base your predictions exactly centered around this live number.\n`
    : '';

  const prompt = `You are an expert in agricultural economics, specializing in predicting crop prices in Indian markets (Agmarknet / MSAMB).

Based on the provided details and the LIVE DATA below, predict the market price range for 7 days from the provided date.

Details:
- Region: ${input.region}
- Crop: ${input.crop}
- Variety: ${input.variety}
- Date: ${input.date}${liveContextText}

CRITICAL RULES:
1. Use the provided LIVE GOVT MANDI DATA as your unwavering baseline for the "currentMandiPrice" value if it exists.
2. The predicted price MUST be evaluated contextually using: predicted_price = current_price * (1 + seasonal_factor + demand_factor - supply_factor).
3. The predicted price MUST NOT deviate more than ±10-15% from the Current Mandi Price unless strongly justified by extreme seasonality.
4. Provide a prediction RANGE (predictedPriceMin and predictedPriceMax) instead of a single number, to reflect market volatility.
5. Provide the percentageChange (positive or negative float) from the current price to the midpoint of your predicted range.
6. Identify the top 3 factors influencing your prediction (e.g. "Monsoon delays").
7. All prices must be integers representing INR per quintal.
8. NEVER output 2600 or 2720 unless it is the EXACT scientifically accurate market price.
9. Generate 'historicalData' array of 7 items showing realistic prices leading UP TO the current date. (Format date as 'MMM DD' e.g. 'Oct 14').
10. Generate 'predictedData' array of 7 items showing realistic prices STARTING FROM the current date forward.

Think carefully about the real-world historical pricing for this specific crop in this specific region in India.
Then, output ONLY the JSON, strictly matching this format (NO markdown fences, NO extra text):

{ "currentMandiPrice": 1234, "predictedPriceMin": 1200, "predictedPriceMax": 1300, "percentageChange": 2.5, "confidence": 0.88, "recommendedListingPrice": 1350, "factors": ["Factor A"], "historicalData": [{"date":"Oct 10", "price":1200}], "predictedData": [{"date":"Oct 17", "price":1250}] }`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
        }),
      }
    );

    if (res.status === 429) {
      console.warn('[Price Prediction] Rate limited. Falling back to rule-based prediction.');
      return getFallbackPrediction(input);
    }

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      console.error('[Price Prediction] API Error:', JSON.stringify(errBody));
      return getFallbackPrediction(input);
    }

    const data = await res.json();
    const text: string = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';

    let jsonStr = text
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/```$/i, '')
      .trim();

    if (!jsonStr.startsWith('{')) {
      const match = jsonStr.match(/\{[\s\S]*\}/);
      if (match) jsonStr = match[0];
    }

    const parsed = JSON.parse(jsonStr);

    // Safety fallback for current mandi price
    const currentPrice = typeof parsed.currentMandiPrice === 'number' ? parsed.currentMandiPrice : 2600;

    return {
      currentMandiPrice: currentPrice,
      predictedPriceMin: typeof parsed.predictedPriceMin === 'number' ? parsed.predictedPriceMin : currentPrice * 0.95,
      predictedPriceMax: typeof parsed.predictedPriceMax === 'number' ? parsed.predictedPriceMax : currentPrice * 1.05,
      percentageChange: typeof parsed.percentageChange === 'number' ? parsed.percentageChange : 0,
      confidence: typeof parsed.confidence === 'number' ? Math.min(Math.max(parsed.confidence, 0), 1) : 0.7,
      recommendedListingPrice: typeof parsed.recommendedListingPrice === 'number' ? parsed.recommendedListingPrice : Math.round(currentPrice * 1.05),
      factors: Array.isArray(parsed.factors) && parsed.factors.length > 0
        ? parsed.factors
        : ['Seasonal demand fluctuations', 'Local transport costs', 'Standard market rates'],
      historicalData: Array.isArray(parsed.historicalData) ? parsed.historicalData : [],
      predictedData: Array.isArray(parsed.predictedData) ? parsed.predictedData : [],
      isLiveMandiData: !!liveMandiPrice,
    };
  } catch (err: any) {
    console.error('[Price Prediction] Error:', err?.message ?? err);
    return getFallbackPrediction(input, liveMandiPrice);
  }
}

// Fallback logic so the app never crashes
function getFallbackPrediction(input: PredictCropPriceInput, liveMandiPrice?: number | null): PredictCropPriceOutput {
  // More intelligent, crop-specific deterministic pricing for fallbacks
  let basePrice = liveMandiPrice ? liveMandiPrice : 2500;

  if (!liveMandiPrice) {
    const lowerCrop = input.crop.toLowerCase();

    if (lowerCrop.includes('wheat') || lowerCrop.includes('gehu')) basePrice = 2520;
    if (lowerCrop.includes('cotton') || lowerCrop.includes('kapas')) basePrice = 7500;
    if (lowerCrop.includes('onion') || lowerCrop.includes('pyaaz')) basePrice = 1800;
    if (lowerCrop.includes('soyabean') || lowerCrop.includes('soybean')) basePrice = 4400;
    if (lowerCrop.includes('rice') || lowerCrop.includes('paddy')) basePrice = 2200;
    if (lowerCrop.includes('maize') || lowerCrop.includes('corn')) basePrice = 2100;
    if (lowerCrop.includes('tur') || lowerCrop.includes('arhar')) basePrice = 9000;
    if (lowerCrop.includes('banana') || lowerCrop.includes('kela')) basePrice = 1450;
    if (lowerCrop.includes('sugarcane') || lowerCrop.includes('ganna')) basePrice = 315;
    if (lowerCrop.includes('tomato') || lowerCrop.includes('tamatar')) basePrice = 1200;
    if (lowerCrop.includes('potato') || lowerCrop.includes('aloo')) basePrice = 1100;
  }



  // Fallback generates a slight fluctuation of ±2-5%
  const fluctuation = (Math.random() * 0.1) - 0.05;

  const midPoint = basePrice * (1 + fluctuation);
  const minPrice = Math.round(midPoint * 0.96);
  const maxPrice = Math.round(midPoint * 1.04);
  const percentChange = Number(((midPoint - basePrice) / basePrice * 100).toFixed(2));

  const historicalData: PriceDataPoint[] = [];
  const predictedData: PriceDataPoint[] = [];

  // Format dates: e.g., "Feb 23"
  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  };

  const today = new Date();

  for (let i = 7; i > 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    historicalData.push({
      date: formatDate(d),
      price: Math.round(basePrice * (1 + (Math.random() * 0.05 - 0.025)))
    });
  }

  for (let i = 1; i <= 7; i++) {
    const d = new Date(today);
    d.setDate(d.getDate() + i);
    predictedData.push({
      date: formatDate(d),
      price: Math.round(midPoint * (1 + (Math.random() * 0.05 - 0.025)))
    });
  }

  return {
    currentMandiPrice: basePrice,
    predictedPriceMin: minPrice,
    predictedPriceMax: maxPrice,
    percentageChange: percentChange,
    confidence: liveMandiPrice ? 0.85 + (Math.random() * 0.1) : 0.6 + (Math.random() * 0.15),
    recommendedListingPrice: Math.round(maxPrice * 1.05),
    factors: [
      `Historical baseline pricing for ${input.crop}`,
      `Regional variations for ${input.region}`,
      'Standard seasonal supply patterns'
    ],
    historicalData,
    predictedData,
    isLiveMandiData: !!liveMandiPrice,
  };
}
