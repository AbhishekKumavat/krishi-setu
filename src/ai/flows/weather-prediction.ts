'use server';

export type WeatherAnalysisOutput = {
  location: string;
  forecast: {
    temperature: number;
    humidity: number;
    windSpeed: number;
    description: string;
    precipitationChance: number;
  };
  recommendations: { category: string; title: string; tip: string }[];
  suitableActivities: string[];
  recommendedCropsForHarvest: string[];
};

// ─── WeatherAPI.com ───────────────────────────────────────────────────────────

async function fetchWeather(location: string) {
  const apiKey = process.env.WEATHER_API_KEY;
  if (!apiKey) return getMockWeather();

  try {
    const url = `https://api.weatherapi.com/v1/forecast.json?key=${apiKey}&q=${encodeURIComponent(location)}&days=1&aqi=no&alerts=no`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`WeatherAPI ${res.status}`);
    const data = await res.json();
    const current = data.current;
    const day = data.forecast?.forecastday?.[0]?.day;
    console.log(`[WeatherAPI] ${location}: ${current?.condition?.text}, ${current?.temp_c}°C`);
    return {
      temperature: parseFloat((current?.temp_c ?? 25).toFixed(1)),
      humidity: Math.round(current?.humidity ?? 60),
      windSpeed: parseFloat((current?.wind_kph ?? 10).toFixed(1)),
      description: (current?.condition?.text ?? 'Clear').toLowerCase(),
      precipitationChance: Math.round(day?.daily_chance_of_rain ?? 0),
    };
  } catch (err: any) {
    console.error('WeatherAPI failed:', err?.message);
    return getMockWeather();
  }
}

function getMockWeather() {
  const conditions = ['clear sky', 'partly cloudy', 'few clouds', 'overcast'];
  return {
    temperature: parseFloat((22 + Math.random() * 8).toFixed(1)),
    humidity: Math.round(55 + Math.random() * 30),
    windSpeed: parseFloat((8 + Math.random() * 12).toFixed(1)),
    description: conditions[Math.floor(Math.random() * conditions.length)],
    precipitationChance: Math.round(Math.random() * 40),
  };
}

// ─── Gemini REST API (direct) ─────────────────────────────────────────────────

async function getAIRecommendations(location: string, weather: ReturnType<typeof getMockWeather>) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return getFallbackRecommendations(location, weather);

  const prompt = `You are an expert agricultural advisor for Indian farmers (Maharashtra region).

Current weather for ${location}:
- Temperature: ${weather.temperature}°C
- Humidity: ${weather.humidity}%
- Wind Speed: ${weather.windSpeed} km/h
- Condition: ${weather.description}
- Chance of Rain: ${weather.precipitationChance}%

Respond with ONLY a valid JSON object, no markdown, no explanation:
{
  "suitableActivities": ["task1", "task2", "task3"],
  "recommendedCropsForHarvest": ["crop1", "crop2"],
  "recommendations": [
    {"category": "Irrigation", "title": "Title here", "tip": "Detailed advice here."},
    {"category": "Pest Control", "title": "Title here", "tip": "Detailed advice here."}
  ]
}

Rules:
- suitableActivities: 2-3 specific tasks (e.g. "Irrigate wheat fields", "Spray neem oil").
- recommendedCropsForHarvest: If location mentions Jalgaon, ALWAYS include Banana (Jalgaon = banana capital of India). Clear/cloudy: Banana, Wheat, Jowar, Onion, Soybean. Humid: Banana, Sugarcane, Rice. Empty ONLY for severe storms.
- recommendations: 2-3 tips with specific crop names, irrigation (drip/flood), fertilizers (urea, DAP).`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.4, maxOutputTokens: 1024 },
        }),
      }
    );

    if (!res.ok) throw new Error(`Gemini API ${res.status}`);
    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    const jsonStr = text.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```$/i, '').trim();
    return JSON.parse(jsonStr);
  } catch (err: any) {
    console.error('Gemini API failed:', err?.message);
    return getFallbackRecommendations(location, weather);
  }
}

function getFallbackRecommendations(location: string, weather: { description: string; windSpeed: number; precipitationChance: number }) {
  const isJalgaon = location.toLowerCase().includes('jalgaon');
  const isSevere = weather.precipitationChance > 70 || weather.windSpeed > 50;

  return {
    suitableActivities: isSevere
      ? ['Stay indoors', 'Inspect stored crops', 'Equipment maintenance']
      : ['Irrigate fields', 'Apply fertilizers', 'Inspect crops for pests'],
    recommendedCropsForHarvest: isSevere
      ? []
      : isJalgaon
        ? ['Banana', 'Onion', 'Wheat']
        : ['Wheat', 'Jowar', 'Chickpea'],
    recommendations: [
      {
        category: 'Irrigation',
        title: 'Use drip irrigation',
        tip: `With ${weather.description} conditions, drip irrigation can save up to 40% water while keeping soil moisture optimal for wheat and onion crops.`,
      },
      {
        category: 'Crop Care',
        title: isJalgaon ? 'Banana bunch protection' : 'Monitor crop health',
        tip: isJalgaon
          ? 'Wrap developing banana bunches with perforated polythene bags to protect from pests and improve bunch quality.'
          : 'Check crops for early signs of pest infestation or fungal disease given current weather conditions.',
      },
    ],
  };
}

// ─── Main Export ──────────────────────────────────────────────────────────────

export async function getWeatherAnalysis(input: { location: string }): Promise<WeatherAnalysisOutput> {
  const weather = await fetchWeather(input.location);
  const advice = await getAIRecommendations(input.location, weather);

  return {
    location: input.location,
    forecast: weather,
    suitableActivities: advice.suitableActivities ?? [],
    recommendedCropsForHarvest: advice.recommendedCropsForHarvest ?? [],
    recommendations: advice.recommendations ?? [],
  };
}
