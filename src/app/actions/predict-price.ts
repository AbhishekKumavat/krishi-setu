'use server';

import {
  predictCropPrice,
  type PredictCropPriceInput,
  type PredictCropPriceOutput,
} from '@/ai/flows/crop-price-prediction';
import { z } from 'zod';

const formSchema = z.object({
  region: z.string().min(1, 'Region is required.'),
  crop: z.string().min(1, 'Crop is required.'),
  variety: z.string().optional().default('FAQ'),
  date: z.date().optional().default(new Date()),
  quantity: z.coerce.number().min(1).default(1000),
});

export async function predictPrice(
  values: z.infer<typeof formSchema>
): Promise<{
  success: boolean;
  data?: PredictCropPriceOutput;
  error?: string;
}> {
  const validatedFields = formSchema.safeParse(values);
  if (!validatedFields.success) {
    return { success: false, error: 'Invalid input.' };
  }

  const input: PredictCropPriceInput = {
    ...validatedFields.data,
    date: validatedFields.data.date.toISOString().split('T')[0], // format to YYYY-MM-DD
  };

  try {
    const result = await predictCropPrice(input);
    return { success: true, data: result };
  } catch (e) {
    console.error(e);
    // In a production app, you'd want to log this error to a monitoring service.
    return { success: false, error: 'Failed to get prediction from AI model.' };
  }
}
