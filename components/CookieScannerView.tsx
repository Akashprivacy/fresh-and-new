import React, { useState, useCallback } from 'react';
import { URLInputForm } from './URLInputForm';
import { ScanResultDisplay } from './ScanResultDisplay';
import { ScanningProgress } from './ScanningProgress';
import { AlertTriangleIcon } from './Icons';
import type { ScanResultData } from '../types';

export const CookieScannerView: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [scanResult, setScanResult] = useState<ScanResultData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = useCallback(async () => {
    if (!url) {
      setError('Please enter a valid website URL.');
      return;
    }
    setError(null);
    setIsLoading(true);
    setScanResult(null);

    try {
      const response = await fetch('http://localhost:3001/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const result: ScanResultData = await response.json();
      setScanResult(result);

    } catch (err) {
      console.error(err);
      const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred during the scan.';
      setError(`Failed to scan website. ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  }, [url]);
  
  return (
    <>
      <div className="max-w-3xl mx-auto mt-6">
        <URLInputForm
          url={url}
          setUrl={setUrl}
          onScan={handleScan}
          isLoading={isLoading}
        />
      </div>

      <div className="mt-12">
        {isLoading && <ScanningProgress />}
        {error && (
          <div className="max-w-4xl mx-auto bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-300 p-4 rounded-lg flex items-start space-x-4" role="alert">
            <AlertTriangleIcon className="h-6 w-6 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-red-800 dark:text-red-200">Scan Error</p>
              <p className="text-sm">{error}</p>
            </div>
          </div>
        )}
        {scanResult && !isLoading && <ScanResultDisplay result={scanResult} scannedUrl={url} />}
        {!isLoading && !error && !scanResult && (
           <div className="text-center text-[var(--text-primary)] mt-16 animate-fade-in-up">
            <p>Your comprehensive compliance report will appear here.</p>
          </div>
        )}
      </div>
    </>
  );
};