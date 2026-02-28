import { DiseaseDiagnosisClient } from '@/components/features/disease-diagnosis-client';

export default function DiseaseDiagnosisPage() {
    return (
        <div className="space-y-8">
            <div className="space-y-2">
                <h1 className="font-headline text-3xl md:text-4xl font-bold tracking-tight">
                    Crop Disease Diagnosis
                </h1>
                <p className="text-muted-foreground">
                    Upload a clear photo of your crop&apos;s affected leaf or stem to get an AI-powered diagnosis and treatment advice.
                </p>
            </div>
            <DiseaseDiagnosisClient />
        </div>
    );
}
