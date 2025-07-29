
import React from 'react';

interface LoadingSpinnerProps {
  text?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ text = 'Analyzing Website...' }) => {
  return (
    <div className="flex flex-col items-center justify-center p-10" aria-label="Loading">
      <div 
        className="w-10 h-10 rounded-full animate-spin"
        style={{
            border: '4px solid var(--border-primary)',
            borderTopColor: 'var(--brand-blue)',
        }}
      ></div>
      <p className="mt-4 text-[var(--text-primary)] font-semibold tracking-wide">{text}</p>
    </div>
  );
};
