'use server';

type RecommendCropPayload = {
    auto_location: boolean;
    latitude?: number;
    longitude?: number;
}

export async function recommendCrop(payload: RecommendCropPayload): Promise<any> {
    const endpoint = 'https://swapcodes-farmingo.hf.space/recommend';
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorBody = await response.text();
            throw new Error(`API Error: ${response.status} ${response.statusText} - ${errorBody}`);
        }

        const responseData = await response.json();

        // Overlay with real-time WeatherAPI to ensure parity with the Weather Prediction tab
        if (payload.latitude && payload.longitude && process.env.WEATHER_API_KEY) {
            try {
                const weatherUrl = `https://api.weatherapi.com/v1/forecast.json?key=${process.env.WEATHER_API_KEY}&q=${payload.latitude},${payload.longitude}&days=1&aqi=no&alerts=no`;
                const weatherRes = await fetch(weatherUrl);
                if (weatherRes.ok) {
                    const realWeather = await weatherRes.json();
                    if (responseData.weather) {
                        responseData.weather.temperature = parseFloat((realWeather?.current?.temp_c ?? responseData.weather.temperature).toFixed(1));
                        responseData.weather.humidity = Math.round(realWeather?.current?.humidity ?? responseData.weather.humidity);

                        const chanceOfRain = realWeather?.forecast?.forecastday?.[0]?.day?.daily_chance_of_rain;
                        if (chanceOfRain !== undefined) {
                            // Approximation to map % chance or expected mm to the API's rainfall param format 
                            // Just directly using daily_chance_of_rain or total precip mm
                            responseData.weather.rainfall = realWeather?.forecast?.forecastday?.[0]?.day?.totalprecip_mm ?? responseData.weather.rainfall;
                        }
                    }
                }
            } catch (wErr) {
                console.warn("Failed to fetch real-time weather override", wErr);
            }
        }

        return responseData;
    } catch (error: any) {
        console.error('Failed to get crop recommendation:', error);
        throw new Error(error.message || 'Failed to fetch from the API endpoint.');
    }
}
