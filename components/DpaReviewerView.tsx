
import React, { useState, useCallback } from 'react';
import type { DpaAnalysisResult, DpaPerspective } from '../types';
import { LoadingSpinner } from './LoadingSpinner';
import { AlertTriangleIcon, DocumentTextIcon } from './Icons';
import { DpaResultDisplay } from './DpaResultDisplay';

export const DpaReviewerView: React.FC = () => {
    const [dpaText, setDpaText] = useState<string>('');
    const [perspective, setPerspective] = useState<DpaPerspective>('controller');
    const [analysisResult, setAnalysisResult] = useState<DpaAnalysisResult | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);

    const handleAnalyze = useCallback(async () => {
        if (!dpaText.trim()) {
            setError('Please paste the DPA text into the text area before analyzing.');
            return;
        }
        setError(null);
        setIsLoading(true);
        setAnalysisResult(null);

        try {
            const response = await fetch('http://localhost:3001/api/review-dpa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dpaText, perspective }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }

            const result: DpaAnalysisResult = await response.json();
            setAnalysisResult(result);

        } catch (err) {
            console.error(err);
            const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred during the analysis.';
            setError(`Failed to analyze DPA. ${errorMessage}`);
        } finally {
            setIsLoading(false);
        }
    }, [dpaText, perspective]);
    
    const PerspectiveRadio: React.FC<{value: DpaPerspective, label: string, description: string}> = ({value, label, description}) => (
      <label htmlFor={`perspective-${value}`} className={`flex items-start p-4 border rounded-lg cursor-pointer transition-colors ${perspective === value ? 'bg-brand-blue/10 border-brand-blue' : 'bg-[var(--bg-primary)] border-[var(--border-primary)] hover:border-slate-400 dark:hover:border-slate-500'}`}>
          <input 
              type="radio" 
              name="perspective" 
              id={`perspective-${value}`}
              value={value} 
              checked={perspective === value} 
              onChange={() => setPerspective(value)}
              className="h-4 w-4 mt-1 text-brand-blue border-gray-300 focus:ring-brand-blue"
          />
          <div className="ml-3 text-sm">
              <span className="font-bold text-[var(--text-headings)]">{label}</span>
              <p className="text-[var(--text-primary)]">{description}</p>
          </div>
      </label>
    );

    return (
        <>
            <div className="max-w-4xl mx-auto mt-6 bg-[var(--bg-secondary)] p-6 rounded-xl border border-[var(--border-primary)] shadow-sm">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label htmlFor="dpa-text" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
                            Paste DPA Text
                        </label>
                        <textarea
                            id="dpa-text"
                            value={dpaText}
                            onChange={(e) => setDpaText(e.target.value)}
                            placeholder="Copy and paste the full text from your Data Processing Agreement document here..."
                            disabled={isLoading}
                            rows={15}
                            className="w-full text-sm bg-[var(--bg-primary)] text-[var(--text-headings)] border border-[var(--border-primary)] rounded-lg focus:ring-2 focus:ring-brand-blue focus:border-brand-blue transition duration-150 ease-in-out disabled:bg-[var(--bg-tertiary)] p-4 font-mono"
                        />
                    </div>
                    <div className="space-y-4">
                        <div>
                           <p className="block text-sm font-medium text-[var(--text-primary)] mb-1">Review Perspective</p>
                           <p className="text-xs text-[var(--text-primary)]/80 mb-2">Select your role to tailor the risk analysis.</p>
                        </div>
                        <div className="space-y-4">
                            <PerspectiveRadio value="controller" label="Data Controller" description="The entity that determines the purposes and means of processing personal data." />
                            <PerspectiveRadio value="processor" label="Data Processor" description="The entity that processes personal data on behalf of the controller." />
                        </div>
                         <button
                            type="button"
                            onClick={handleAnalyze}
                            disabled={isLoading || !dpaText.trim()}
                            className="w-full flex items-center justify-center gap-2 mt-6 px-6 py-3 font-semibold text-white bg-brand-blue rounded-md shadow-lg shadow-blue-500/20 dark:shadow-blue-500/10 hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-secondary)] focus:ring-brand-blue transition-all duration-200 disabled:bg-slate-400 dark:disabled:bg-slate-600 disabled:shadow-none disabled:cursor-not-allowed"
                        >
                           <DocumentTextIcon className="h-5 w-5" />
                           {isLoading ? 'Analyzing DPA...' : 'Analyze DPA'}
                        </button>
                    </div>
                </div>
            </div>

            <div className="mt-12">
                {isLoading && <LoadingSpinner text="Analyzing DPA... This may take a moment." />}
                {error && (
                    <div className="max-w-4xl mx-auto bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-300 p-4 rounded-lg flex items-start space-x-4" role="alert">
                        <AlertTriangleIcon className="h-6 w-6 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" />
                        <div>
                            <p className="font-bold text-red-800 dark:text-red-200">Analysis Error</p>
                            <p className="text-sm">{error}</p>
                        </div>
                    </div>
                )}
                {analysisResult && !isLoading && <DpaResultDisplay result={analysisResult} perspective={perspective} />}
                {!isLoading && !error && !analysisResult && (
                    <div className="text-center text-[var(--text-primary)] mt-16 animate-fade-in-up">
                        <p>Your DPA analysis report will appear here.</p>
                    </div>
                )}
            </div>
        </>
    );
};
