import React, { useState, useEffect } from 'react';

// Data for the component
const privacyQuotes = [
  { quote: "Privacy is not an option, and it shouldn't be the price we accept for just getting on the Internet.", author: "Gary Kovacs" },
  { quote: "Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say.", author: "Edward Snowden" },
  { quote: "The distinction between what is public and what is private is not a new one, but the new technologies have redefined it, and we need to rethink the boundary.", author: "Padmasree Warrior" },
  { quote: "If you're not paying for the product, you are the product.", author: "Tristan Harris" },
  { quote: "Data is the new oil. It’s valuable, but if unrefined it cannot really be used.", author: "Clive Humby" }
];

const scanSteps = [
    { message: 'Initializing secure scanner...', progress: 10 },
    { message: 'Requesting website content...', progress: 25 },
    { message: 'Analyzing pre-consent technologies...', progress: 45 },
    { message: 'Simulating consent rejection...', progress: 60 },
    { message: 'Analyzing post-rejection state...', progress: 75 },
    { message: 'Calling AI for compliance analysis...', progress: 90 },
    { message: 'Finalizing your report...', progress: 99 },
];

export const ScanningProgress: React.FC = () => {
    const [currentStep, setCurrentStep] = useState(0);
    const [currentQuoteIndex, setCurrentQuoteIndex] = useState(0);
    const [fadeState, setFadeState] = useState('opacity-100');

    // Effect for cycling through scan steps
    useEffect(() => {
        const stepInterval = setInterval(() => {
            setCurrentStep(prev => (prev < scanSteps.length - 1 ? prev + 1 : prev));
        }, 2000); // Progress every 2s

        return () => clearInterval(stepInterval);
    }, []);
    
    // Effect for cycling through quotes
    useEffect(() => {
        const quoteInterval = setInterval(() => {
            setFadeState('opacity-0');
            setTimeout(() => {
                setCurrentQuoteIndex(prev => (prev + 1) % privacyQuotes.length);
                setFadeState('opacity-100');
            }, 500); // 0.5s for fade out
        }, 5000); // Change quote every 5s

        return () => clearInterval(quoteInterval);
    }, []);

    const { message, progress } = scanSteps[currentStep];
    const currentQuote = privacyQuotes[currentQuoteIndex];

    return (
        <div className="flex flex-col items-center justify-center p-10 max-w-2xl mx-auto animate-fade-in-up" aria-live="polite">
            <h3 className="text-xl font-bold text-[var(--text-headings)] mb-4">{message}</h3>
            <div className="w-full bg-[var(--bg-secondary)] rounded-full h-4 mb-6 border border-[var(--border-primary)] overflow-hidden">
                <div 
                    className="bg-brand-blue h-full rounded-full transition-all duration-1000 ease-out" 
                    style={{ width: `${progress}%` }}
                    role="progressbar"
                    aria-label="Scan progress"
                    aria-valuenow={progress}
                    aria-valuemin={0}
                    aria-valuemax={100}
                ></div>
            </div>
            
            <div className={`text-center transition-opacity duration-500 ease-in-out ${fadeState}`}>
                <blockquote className="text-lg italic text-[var(--text-primary)]">
                  <p>"{currentQuote.quote}"</p>
                </blockquote>
                <cite className="mt-2 text-sm font-semibold text-[var(--text-headings)] not-italic">- {currentQuote.author}</cite>
            </div>
        </div>
    );
};
