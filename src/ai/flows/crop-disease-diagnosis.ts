'use server';

export type DiagnoseCropDiseaseInput = {
  photoDataUri: string;
};

export type DiagnoseCropDiseaseOutput = {
  diseaseName: string;
  confidence: number;
  affectedSeverity: string;
  immediateSteps: string;
  followUpSteps: string;
  communityPostsLink: string;
};

export async function diagnoseCropDisease(
  input: DiagnoseCropDiseaseInput
): Promise<DiagnoseCropDiseaseOutput> {
  const apiKey = process.env.GEMINI_API_KEY;
  console.log('[Disease Diagnosis] Starting... API key present:', !!apiKey, '| Image length:', input.photoDataUri?.length);

  if (!apiKey) {
    return errorFallback('GEMINI_API_KEY is not configured on the server.');
  }

  // Parse the data URI into mimeType + base64 data
  const matches = input.photoDataUri.match(/^data:([^;]+);base64,(.+)$/);
  if (!matches) {
    return errorFallback('Invalid image format. Please upload a JPG, PNG, or WebP image.');
  }
  const mimeType = matches[1];
  const base64Data = matches[2];
  console.log('[Disease Diagnosis] Image mimeType:', mimeType, '| base64 length:', base64Data.length);

  const prompt = `You are a highly experienced plant pathologist and agronomist with expertise in diagnosing crop diseases in Indian agriculture.

CAREFULLY examine the plant image and follow these steps:

STEP 1 - OBSERVE the visual symptoms:
- Look at the COLOR of affected areas (yellow, brown, black, white, purple, orange)
- Examine the PATTERN of spots (circular, angular, irregular, water-soaked)
- Check if spots have distinct BORDERS or halos
- Note if there is any MOLD, POWDER, or FUNGAL growth visible
- Observe which PART is affected (leaf edges, center, stem, fruit, root)
- Check severity: what % of the plant is affected?

STEP 2 - IDENTIFY the crop type from the image if possible.

STEP 3 - Give the MOST ACCURATE diagnosis based on well-known crop diseases. Common Indian crop diseases include:
- Chilli: Anthracnose, Cercospora Leaf Spot, Bacterial Wilt, Powdery Mildew, Fusarium Wilt, Chilli Mosaic Virus
- Tomato: Early Blight, Late Blight, Leaf Curl Virus, Fusarium Wilt, Bacterial Canker
- Wheat: Rust (Yellow/Brown/Black), Powdery Mildew, Karnal Bunt, Loose Smut
- Rice: Blast, Brown Spot, Sheath Blight, BLB, False Smut
- Maize: Northern Leaf Blight, Gray Leaf Spot, Common Rust, Downy Mildew
- Cotton: Bacterial Blight, Root Rot, Leaf Curl Virus, Fusarium Wilt
- Banana: Sigatoka (Black/Yellow), Panama Wilt, Bunchy Top, Anthracnose
- Potato: Late Blight, Early Blight, Common Scab, Black Leg

Respond with ONLY a valid JSON object (no markdown, no explanation):
{
  "diseaseName": "Precise disease name (e.g. 'Chilli Anthracnose (Colletotrichum capsici)')",
  "confidence": 0.88,
  "affectedSeverity": "Mild / Moderate / Severe",
  "immediateSteps": "Specific immediate actions: which pesticide/fungicide to apply, dosage, how to apply. Include brand names available in India.",
  "followUpSteps": "Follow-up actions over next 2 weeks: monitoring, re-application schedule, preventive measures.",
  "communityPostsLink": "/community?search=disease-name-slug"
}

IMPORTANT:
- Be SPECIFIC — don't just say 'Leaf Spot', identify the exact pathogen if possible.
- confidence must be 0.0–1.0. If genuinely unsure, set 0.5–0.6.
- If the image is unclear or too blurry to diagnose, say diseaseName='Unable to diagnose - image unclear' and confidence=0.3.
- If plant appears healthy with no disease symptoms, say diseaseName='Healthy Plant' and confidence=0.95.
- Give India-specific treatment advice (e.g., Dithane M-45, Bavistin, Captan, Copper Oxychloride).`;

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                { text: prompt },
                { inlineData: { mimeType, data: base64Data } },
              ],
            },
          ],
          generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
        }),
      }
    );

    console.log('[Disease Diagnosis] Gemini response status:', res.status);

    if (res.status === 429) {
      // Rate limit — wait 45s and retry once
      console.warn('[Disease Diagnosis] Rate limited, waiting 45s before retry...');
      await new Promise(r => setTimeout(r, 45000));
      return diagnoseCropDisease(input);
    }

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const errMsg = (errBody as any)?.error?.message ?? JSON.stringify(errBody);
      console.error('[Disease Diagnosis] Gemini API error:', errMsg);
      return errorFallback(`Gemini API error ${res.status}: ${errMsg}`);
    }

    const data = await res.json();
    const text: string = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    console.log('[Disease Diagnosis] Raw AI text:', text.slice(0, 400));

    // Extract JSON — strip markdown fences, then find first { ... }
    let jsonStr = text
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/```$/i, '')
      .trim();

    if (!jsonStr.startsWith('{')) {
      const match = jsonStr.match(/\{[\s\S]*\}/);
      if (match) jsonStr = match[0];
    }

    let parsed: any = {};
    try {
      parsed = JSON.parse(jsonStr);
    } catch {
      console.error('[Disease Diagnosis] JSON parse failed. Raw text:', text);
      return errorFallback('AI response could not be parsed. Please try again with a clearer image.');
    }

    return {
      diseaseName: parsed.diseaseName ?? 'Could not determine disease',
      confidence: typeof parsed.confidence === 'number' ? Math.min(Math.max(parsed.confidence, 0), 1) : 0.5,
      affectedSeverity: parsed.affectedSeverity ?? 'Unknown',
      immediateSteps: parsed.immediateSteps ?? 'Consult a local agricultural extension officer.',
      followUpSteps: parsed.followUpSteps ?? 'Monitor the plant closely over the next 2 weeks.',
      communityPostsLink: parsed.communityPostsLink ?? '/community',
    };
  } catch (err: any) {
    console.error('[Disease Diagnosis] Unexpected error:', err?.message ?? err);
    return errorFallback(err?.message ?? 'Unexpected error during diagnosis.');
  }
}

function errorFallback(reason: string): DiagnoseCropDiseaseOutput {
  return {
    diseaseName: 'Diagnosis Unavailable',
    confidence: 0,
    affectedSeverity: 'Unknown',
    immediateSteps: `Could not complete diagnosis. Reason: ${reason}`,
    followUpSteps: 'Please try again with a clearer, well-lit photo of the affected plant area.',
    communityPostsLink: '/community',
  };
}
