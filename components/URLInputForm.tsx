
import React from 'react';
import { SearchIcon } from './Icons';

interface URLInputFormProps {
  url: string;
  setUrl: (url: string) => void;
  onScan: () => void;
  isLoading: boolean;
}

export const URLInputForm: React.FC<URLInputFormProps> = ({ url, setUrl, onScan, isLoading }) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScan();
  };

  return (
    <form onSubmit={handleSubmit} className="w-full bg-[var(--bg-secondary)] p-6 rounded-xl border border-[var(--border-primary)] shadow-sm">
      <label htmlFor="url-input" className="block text-sm font-medium text-[var(--text-primary)] mb-1">
        Website URL
      </label>
      <div className="relative">
        <div className="pointer-events-none absolute inset-y-0 left-0 pl-4 flex items-center">
          <SearchIcon className="h-5 w-5 text-gray-400" />
        </div>
        <input
          id="url-input"
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="e.g., https://www.example.com"
          required
          disabled={isLoading}
          className="w-full pl-11 pr-36 py-3 text-base bg-[var(--bg-primary)] text-[var(--text-headings)] border border-[var(--border-primary)] rounded-lg focus:ring-2 focus:ring-brand-blue focus:border-brand-blue transition duration-150 ease-in-out disabled:bg-[var(--bg-tertiary)]"
        />
        <button
          type="submit"
          disabled={isLoading}
          className="absolute inset-y-0 right-0 flex items-center justify-center px-6 m-1.5 font-semibold text-white bg-brand-blue rounded-md shadow-lg shadow-blue-500/20 dark:shadow-blue-500/10 hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-secondary)] focus:ring-brand-blue transition-all duration-200 disabled:bg-slate-400 dark:disabled:bg-slate-600 disabled:shadow-none disabled:cursor-not-allowed"
        >
          {isLoading ? 'Scanning...' : 'Scan Website'}
        </button>
      </div>
    </form>
  );
};
