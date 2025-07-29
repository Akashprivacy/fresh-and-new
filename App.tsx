
import React, { useState, useCallback, useEffect } from 'react';
import { CookieCareLogo, SunIcon, MoonIcon, CheckCircleIcon, DocumentTextIcon, ShieldCheckIcon } from './components/Icons';
import { CookieScannerView } from './components/CookieScannerView';
import { DpaReviewerView } from './components/DpaReviewerView';
import { VulnerabilityScannerView } from './components/VulnerabilityScannerView';

const ThemeToggle: React.FC<{ theme: string, toggleTheme: () => void }> = ({ theme, toggleTheme }) => (
    <button
        onClick={toggleTheme}
        className="p-2 rounded-full text-[var(--text-primary)] hover:bg-[var(--bg-secondary)] transition-colors"
        aria-label="Toggle theme"
    >
        {theme === 'dark' ? <SunIcon className="h-5 w-5" /> : <MoonIcon className="h-5 w-5" />}
    </button>
);

type View = 'scanner' | 'dpa' | 'vulnerability';

const App: React.FC = () => {
  const [theme, setTheme] = useState('dark');
  const [activeView, setActiveView] = useState<View>('scanner');

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(savedTheme);
    document.documentElement.classList.toggle('dark', savedTheme === 'dark');
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
    document.documentElement.classList.toggle('dark', newTheme === 'dark');
  };

  const NavTab: React.FC<{view: View, label: string, icon: React.ReactNode}> = ({ view, label, icon }) => {
    const isActive = activeView === view;
    return (
       <button 
          onClick={() => setActiveView(view)}
          className={`flex items-center space-x-2 px-4 py-2.5 text-sm font-semibold rounded-md transition-colors duration-200 ${
            isActive 
              ? 'bg-brand-blue text-white shadow-sm' 
              : 'text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]'
          }`}
          aria-current={isActive ? 'page' : undefined}
       >
        {icon}
        <span>{label}</span>
      </button>
    )
  }
  
  const descriptions: Record<View, string> = {
    scanner: "Real-time reports on cookies, trackers, and privacy risks for GDPR & CCPA.",
    dpa: "AI-powered analysis of Data Processing Agreements to identify legal risks.",
    vulnerability: "AI-driven security scans to find website vulnerabilities and get remediation plans."
  }

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] font-sans text-[var(--text-primary)] flex flex-col">
      <header className="bg-[var(--bg-primary)]/80 backdrop-blur-sm sticky top-0 z-50 border-b border-[var(--border-primary)]">
        <nav className="container mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <CookieCareLogo className="h-8 w-auto text-brand-blue" />
            <h1 className="text-xl font-bold text-[var(--text-headings)] tracking-tight">
              Cookie Care
            </h1>
          </div>
          <ThemeToggle theme={theme} toggleTheme={toggleTheme} />
        </nav>
      </header>

      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 flex-grow">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[var(--text-headings)] leading-tight">
            Holistic Compliance Analysis Engine
          </h2>
          <p className="mt-4 text-lg text-[var(--text-primary)] max-w-2xl mx-auto">
            {descriptions[activeView]}
          </p>
        </div>

        <div className="max-w-4xl mx-auto mt-10">
          <div className="flex justify-center items-center p-1.5 bg-[var(--bg-tertiary)] rounded-lg space-x-2 flex-wrap">
            <NavTab view="scanner" label="Cookie Scanner" icon={<CheckCircleIcon className="h-5 w-5"/>} />
            <NavTab view="dpa" label="DPA Reviewer" icon={<DocumentTextIcon className="h-5 w-5" />} />
            <NavTab view="vulnerability" label="Vulnerability Scanner" icon={<ShieldCheckIcon className="h-5 w-5" />} />
          </div>
        </div>

        <div className="mt-8">
            {activeView === 'scanner' && <CookieScannerView />}
            {activeView === 'dpa' && <DpaReviewerView />}
            {activeView === 'vulnerability' && <VulnerabilityScannerView />}
        </div>
      </main>

      <footer className="text-center py-6 text-sm text-[var(--text-primary)]/80">
        <p>&copy; {new Date().getFullYear()} Cookie Care. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default App;
