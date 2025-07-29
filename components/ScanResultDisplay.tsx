
import React, { useState, useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import type { ScanResultData, CookieInfo, RiskLevel, ComplianceInfo, TrackerInfo, ComplianceStatus } from '../types';
import { CookieCategory, FilterCategory } from '../types';
import { 
  AnalyticsIcon, MarketingIcon, FunctionalIcon, NecessaryIcon, UnknownIcon, 
  AlertOctagonIcon, CheckCircleIcon, FileTextIcon, CookieCareLogo, CodeBracketIcon,
  ShieldExclamationIcon, BanIcon,
  AlertTriangleIcon
} from './Icons';

// --- STYLING HELPERS ---
const getCategoryStyle = (category: CookieCategory | string) => {
  switch (category) {
    case CookieCategory.NECESSARY: return { bgColor: 'bg-blue-100 dark:bg-blue-900/30', textColor: 'text-blue-800 dark:text-blue-300', icon: <NecessaryIcon className="h-4 w-4" />, color: 'hsl(210, 90%, 50%)' };
    case CookieCategory.ANALYTICS: return { bgColor: 'bg-green-100 dark:bg-green-900/30', textColor: 'text-green-800 dark:text-green-300', icon: <AnalyticsIcon className="h-4 w-4" />, color: 'hsl(140, 70%, 45%)' };
    case CookieCategory.MARKETING: return { bgColor: 'bg-orange-100 dark:bg-orange-900/30', textColor: 'text-orange-800 dark:text-orange-300', icon: <MarketingIcon className="h-4 w-4" />, color: 'hsl(30, 90%, 55%)' };
    case CookieCategory.FUNCTIONAL: return { bgColor: 'bg-purple-100 dark:bg-purple-900/30', textColor: 'text-purple-800 dark:text-purple-300', icon: <FunctionalIcon className="h-4 w-4" />, color: 'hsl(260, 80%, 65%)' };
    default: return { bgColor: 'bg-slate-200 dark:bg-slate-700', textColor: 'text-slate-800 dark:text-slate-300', icon: <UnknownIcon className="h-4 w-4" />, color: 'hsl(220, 10%, 50%)' };
  }
};

const getRiskStyle = (riskLevel: RiskLevel) => {
    switch (riskLevel) {
        case 'High': return { color: 'text-red-600 dark:text-red-400', borderColor: 'border-red-500/30 dark:border-red-500/50', bgColor: 'bg-red-50 dark:bg-red-900/20' };
        case 'Medium': return { color: 'text-orange-600 dark:text-orange-400', borderColor: 'border-orange-500/30 dark:border-orange-500/50', bgColor: 'bg-orange-50 dark:bg-orange-900/20' };
        case 'Low': return { color: 'text-green-600 dark:text-green-400', borderColor: 'border-green-500/30 dark:border-green-500/50', bgColor: 'bg-green-50 dark:bg-green-900/20' };
        default: return { color: 'text-slate-600 dark:text-slate-400', borderColor: 'border-slate-300 dark:border-slate-700', bgColor: 'bg-slate-100 dark:bg-slate-800/50' };
    }
};

// --- SUB-COMPONENTS ---

const MethodologyInfoBox: React.FC<{onDismiss: () => void}> = ({ onDismiss }) => (
    <div className="bg-brand-blue/5 dark:bg-brand-blue/10 border border-brand-blue/20 rounded-lg p-5 mb-8 relative">
        <button onClick={onDismiss} className="absolute top-3 right-3 text-[var(--text-primary)] hover:text-[var(--text-headings)] transition-colors" aria-label="Dismiss">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
        <h4 className="font-bold text-lg text-brand-blue dark:text-blue-300 mb-2">How to Read This Report</h4>
        <div className="text-sm text-[var(--text-primary)] space-y-3">
             <p>This report uses a unique **three-stage scan** to find violations that basic tools miss by simulating a real user's journey:</p>
             <ul className="list-disc list-inside space-y-1 pl-2">
                 <li><strong className="text-[var(--text-headings)]">Pre-Consent:</strong> Analyzes technologies loaded <span className="font-semibold text-red-500">before</span> a user interacts with the consent banner.</li>
                 <li><strong className="text-[var(--text-headings)]">Post-Rejection:</strong> Analyzes technologies loaded <span className="font-semibold text-orange-500">after</span> a user rejects consent.</li>
                 <li><strong className="text-[var(--text-headings)]">Post-Acceptance:</strong> Analyzes all technologies loaded <span className="font-semibold text-green-500">after</span> a user accepts consent.</li>
             </ul>
            <p>A technology is marked as <strong className="text-green-600 dark:text-green-400">Compliant</strong> if it's either essential for the site to work ('Necessary') or if it correctly waits for user consent before loading.</p>
        </div>
    </div>
);

const PDFReportHeader: React.FC = () => (
    <div className="hidden print:flex items-center justify-between p-8 border-b border-[var(--border-primary)] mb-6 bg-[var(--bg-primary)]">
        <div className="flex items-center space-x-3">
            <CookieCareLogo className="h-10 w-auto text-brand-blue" />
            <h2 className="text-3xl font-bold text-[var(--text-headings)]">Cookie Care Report</h2>
        </div>
    </div>
);

const WebsiteScreenshot: React.FC<{ base64: string; url: string }> = ({ base64, url }) => (
    <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm">
        <div className="p-5 border-b border-[var(--border-primary)]">
            <h4 className="text-xl font-bold text-[var(--text-headings)]">Website Screenshot</h4>
            <p className="text-sm text-[var(--text-primary)]">Consent banner as seen by the scanner.</p>
        </div>
        <div className="p-2 bg-[var(--bg-tertiary)]">
            <a href={url} target="_blank" rel="noopener noreferrer" title="View live site">
                <img 
                    src={`data:image/jpeg;base64,${base64}`} 
                    alt={`Screenshot of ${url}`} 
                    className="rounded-md border-2 border-white/10 shadow-lg"
                    loading="lazy"
                />
            </a>
        </div>
    </div>
);


const CategoryBadge: React.FC<{ category: CookieCategory | string }> = ({ category }) => {
  const { bgColor, textColor, icon } = getCategoryStyle(category);
  return (
    <span className={`inline-flex items-center gap-x-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${bgColor} ${textColor}`}>
      {icon}
      {category}
    </span>
  );
};

const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) => {
    if (!percent || percent < 0.05) {
        return null;
    }
    const radius = innerRadius + (outerRadius - innerRadius) * 0.6;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
        <text
            x={x}
            y={y}
            fill="white"
            textAnchor="middle"
            dominantBaseline="central"
            className="text-sm font-bold pointer-events-none"
            style={{ textShadow: '0px 1px 3px rgba(0, 0, 0, 0.5)' }}
        >
            {`${(percent * 100).toFixed(0)}%`}
        </text>
    );
};

const TechPieChart: React.FC<{ items: (CookieInfo | TrackerInfo)[] }> = ({ items }) => {
    const data = useMemo(() => {
        const counts = items.reduce((acc, item) => {
            const category = item.category || CookieCategory.UNKNOWN;
            acc[category] = (acc[category] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);
        return Object.entries(counts).map(([name, value]) => ({ name, value, fill: getCategoryStyle(name).color }));
    }, [items]);

    if (!items.length) return null;

    return (
        <div className="h-80 w-full">
            <ResponsiveContainer>
                <PieChart>
                    <Pie 
                        data={data} 
                        dataKey="value" 
                        nameKey="name" 
                        cx="50%" 
                        cy="50%" 
                        innerRadius={0}
                        outerRadius={110}
                        paddingAngle={2} 
                        labelLine={false} 
                        label={renderCustomizedLabel}
                    >
                        {data.map((entry) => <Cell key={`cell-${entry.name}`} fill={entry.fill} stroke="var(--pie-stroke-color)" strokeWidth={2} />)}
                    </Pie>
                    <Tooltip 
                        contentStyle={{ 
                            backgroundColor: 'var(--bg-tertiary)', 
                            color: 'var(--text-primary)', 
                            border: '1px solid var(--border-primary)', 
                            backdropFilter: 'blur(4px)', 
                            borderRadius: '0.5rem',
                            opacity: 0.95
                        }} 
                        itemStyle={{ color: 'var(--text-headings)' }} 
                        labelStyle={{ color: 'var(--text-headings)', fontWeight: 'bold' }} 
                    />
                    <Legend 
                        iconType="circle" 
                        wrapperStyle={{
                            paddingTop: '20px'
                        }}
                    />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
};


const ComplianceCard: React.FC<{ title: string; data: ComplianceInfo }> = ({ title, data }) => {
    const { color, borderColor, bgColor } = getRiskStyle(data.riskLevel);
    return (
        <div className={`rounded-lg border ${borderColor} ${bgColor}`}>
            <div className={`p-4 border-b ${borderColor}`}>
                <h4 className="font-semibold text-[var(--text-headings)]">{title} Compliance</h4>
                <p className={`text-2xl font-bold mt-1 ${color}`}>{data.riskLevel} Risk</p>
            </div>
            <div className="p-4 text-sm text-[var(--text-primary)] space-y-2">
               <p>{data.assessment}</p>
            </div>
        </div>
    );
};

const SummaryCard: React.FC<{ title: string; value: string | number; icon: React.ReactNode }> = ({ title, value, icon }) => (
    <div className="bg-[var(--bg-secondary)] rounded-lg p-5 border border-[var(--border-primary)] shadow-sm">
        <div className="flex items-center">
            {icon}
            <p className="text-sm font-medium text-[var(--text-primary)]">{title}</p>
        </div>
        <p className="mt-2 text-3xl font-bold text-[var(--text-headings)]">{value}</p>
    </div>
);

interface ConsentStatusProps {
    status: ComplianceStatus;
    category: CookieCategory | string;
}

const ConsentStatus: React.FC<ConsentStatusProps> = ({ status, category }) => {
    switch (status) {
        case 'Pre-Consent Violation':
            return (
                <div className="flex items-center space-x-2 text-red-600 dark:text-red-400" title="Violation: This non-essential technology was loaded before the user gave consent.">
                    <AlertOctagonIcon className="h-5 w-5 flex-shrink-0" />
                    <span className="text-xs font-semibold">Pre-Consent</span>
                </div>
            );
        case 'Post-Rejection Violation':
            return (
                <div className="flex items-center space-x-2 text-orange-600 dark:text-orange-400" title="Violation: This non-essential technology was loaded after the user rejected consent.">
                    <BanIcon className="h-5 w-5 flex-shrink-0" />
                    <span className="text-xs font-semibold">Post-Rejection</span>
                </div>
            );
        case 'Compliant':
            const compliantReason = category === CookieCategory.NECESSARY
                ? "This is an essential technology required for the website to function correctly."
                : "This technology was correctly loaded only after user consent was given.";
            return (
                <div className="flex items-center text-green-600 dark:text-green-500" title={compliantReason}>
                    <CheckCircleIcon className="h-5 w-5"/>
                    <span className="text-xs font-semibold ml-2">Compliant</span>
                </div>
            );
        default:
             return (
                <div className="flex items-center space-x-2 text-slate-500" title="Compliance status could not be determined for this technology.">
                    <UnknownIcon className="h-5 w-5 flex-shrink-0" />
                    <span className="text-xs font-semibold">Unknown</span>
                </div>
            );
    }
}

// --- MAIN COMPONENT ---
export const ScanResultDisplay: React.FC<{ result: ScanResultData; scannedUrl: string }> = ({ result, scannedUrl }) => {
  const [activeFilter, setActiveFilter] = useState<FilterCategory>(FilterCategory.ALL);
  const [isExporting, setIsExporting] = useState(false);
  const [showInfoBox, setShowInfoBox] = useState(true);

  const violations = useMemo(() => {
    const cookies = result.cookies.filter(c => c.complianceStatus !== 'Compliant');
    const trackers = result.trackers.filter(t => t.complianceStatus !== 'Compliant');
    return [...cookies, ...trackers];
  }, [result]);

  const filteredData = useMemo(() => {
    const allItems = { cookies: result.cookies, trackers: result.trackers };
    switch(activeFilter) {
      case FilterCategory.ALL: 
        return { ...allItems, title: 'All Technologies' };
      case FilterCategory.TRACKERS: 
        return { cookies: [], trackers: result.trackers, title: 'Network Trackers' };
      case FilterCategory.VIOLATIONS: 
        return { 
          cookies: result.cookies.filter(c => c.complianceStatus !== 'Compliant'),
          trackers: result.trackers.filter(t => t.complianceStatus !== 'Compliant'),
          title: 'Compliance Violations'
        };
      default: // Category filters
        return {
          cookies: result.cookies.filter(cookie => cookie.category === activeFilter),
          trackers: result.trackers.filter(tracker => tracker.category === activeFilter),
          title: `${activeFilter} Technologies`
        };
    }
  }, [result, activeFilter]);
  
  const handleExportPDF = async () => {
    setIsExporting(true);
    const input = document.getElementById('pdf-export-area');
    if (!input) {
      setIsExporting(false);
      return;
    }

    // Temporarily apply styles for full content rendering
    input.classList.add('is-exporting');
    const header = document.getElementById('pdf-header');
    if (header) header.style.display = 'flex';
    await new Promise(resolve => setTimeout(resolve, 100)); // allow DOM to update

    const currentTheme = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
    const bgColor = currentTheme === 'dark' ? '#1c2128' : '#ffffff'; // Use hex for jspdf

    try {
      // Initialize jsPDF with standard A4 settings
      const pdf = new jsPDF({
        orientation: 'p',
        unit: 'pt',
        format: 'a4',
      });
      
      // Use the .html() method for rendering with automatic pagination
      await pdf.html(input, {
        html2canvas: {
          scale: 0.6, // Adjust scale for better quality/size balance
          useCORS: true,
          backgroundColor: bgColor,
          logging: false,
          windowWidth: 1400 // Set a virtual width for responsive layout
        },
        autoPaging: 'slice', // Enable automatic pagination
        width: 515, // Content width (A4 width 595.28pt - 80pt margins)
        margin: [40, 40, 40, 40],
      });

      pdf.save(`CookieCare_Report_${new URL(scannedUrl).hostname}.pdf`);

    } catch (error) {
      console.error("Error generating PDF:", error);
      alert("There was an error generating the PDF. Please try again.");
    } finally {
      if (header) header.style.display = 'none';
      input.classList.remove('is-exporting');
      setIsExporting(false);
    }
  };
  
  
  const getCount = (category: FilterCategory) => {
    if (category === FilterCategory.TRACKERS) return result.trackers.length;
    if (category === FilterCategory.VIOLATIONS) return violations.length;
    const allItems = [...result.cookies, ...result.trackers];
    return allItems.filter(item => item.category === category).length;
  }
  
  const filters = [
    { id: FilterCategory.ALL, label: 'All', count: result.cookies.length + result.trackers.length },
    { id: FilterCategory.TRACKERS, label: 'Trackers', count: result.trackers.length },
    { id: FilterCategory.VIOLATIONS, label: 'Violations', count: violations.length, highlight: true },
    { id: FilterCategory.NECESSARY, label: 'Necessary', count: getCount(FilterCategory.NECESSARY) },
    { id: FilterCategory.ANALYTICS, label: 'Analytics', count: getCount(FilterCategory.ANALYTICS) },
    { id: FilterCategory.MARKETING, label: 'Marketing', count: getCount(FilterCategory.MARKETING) },
    { id: FilterCategory.FUNCTIONAL, label: 'Functional', count: getCount(FilterCategory.FUNCTIONAL) },
  ];

  return (
    <>
      <style>{`
        .is-exporting .overflow-x-auto {
          overflow-x: visible !important;
        }
        .is-exporting {
          /* When exporting, ensure the background color is set for html2canvas */
          background-color: var(--bg-primary);
        }
      `}</style>
      <div className="max-w-7xl mx-auto animate-fade-in-up">
        <div className="flex justify-between items-start mb-6">
          <div>
              <h3 className="text-2xl font-bold text-[var(--text-headings)]">Compliance Dashboard</h3>
              <p className="text-[var(--text-primary)] mt-1">
              Report for: <a href={scannedUrl} target="_blank" rel="noopener noreferrer" className="font-semibold text-brand-blue hover:underline">{scannedUrl}</a>
              </p>
          </div>
          <button
            onClick={handleExportPDF}
            disabled={isExporting}
            className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-brand-blue rounded-md shadow-lg shadow-blue-500/20 dark:shadow-blue-500/10 hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-primary)] focus:ring-brand-blue transition-all disabled:bg-slate-400 dark:disabled:bg-slate-600"
          >
            <FileTextIcon className="h-4 w-4" />
            {isExporting ? 'Exporting...' : 'Export to PDF'}
          </button>
        </div>
        
        {showInfoBox && <MethodologyInfoBox onDismiss={() => setShowInfoBox(false)} />}
        
        <div id="pdf-export-area" className="p-2 sm:p-0">
          <div id="pdf-header" style={{display: 'none'}}><PDFReportHeader /></div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 space-y-8">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                      <SummaryCard title="Total Cookies" value={result.cookies.length} icon={<div className="bg-blue-100 dark:bg-blue-900/30 rounded-full p-2 mr-4"><CheckCircleIcon className="h-6 w-6 text-blue-600 dark:text-blue-300" /></div>} />
                      <SummaryCard title="Network Trackers" value={result.trackers.length} icon={<div className="bg-cyan-100 dark:bg-cyan-900/30 rounded-full p-2 mr-4"><CodeBracketIcon className="h-6 w-6 text-cyan-600 dark:text-cyan-300" /></div>} />
                      <SummaryCard title="Compliance Violations" value={violations.length} icon={<div className="bg-red-100 dark:bg-red-900/30 rounded-full p-2 mr-4"><ShieldExclamationIcon className="h-6 w-6 text-red-600 dark:text-red-300" /></div>} />
                  </div>
                  
                  <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm overflow-hidden">
                      <div className="p-5 border-b border-[var(--border-primary)]">
                          <h4 className="text-xl font-bold text-[var(--text-headings)]">Technology Analysis</h4>
                      </div>
                      <div className="px-5 pt-5">
                          <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border-primary)] pb-4">
                              {filters.map(filter => {
                                  if (filter.count === 0 && ![FilterCategory.ALL, FilterCategory.VIOLATIONS, FilterCategory.TRACKERS].includes(filter.id as FilterCategory)) return null;
                                  const isActive = activeFilter === filter.id;
                                  const isHighlight = filter.highlight && filter.count > 0;
                                  return (
                                  <button
                                      key={filter.id}
                                      onClick={() => setActiveFilter(filter.id)}
                                      className={`px-4 py-2 text-sm font-semibold rounded-full transition-colors duration-150 flex items-center ${
                                          isActive ? (isHighlight ? 'bg-red-600 text-white shadow-sm' : 'bg-brand-blue text-white shadow-sm')
                                          : (isHighlight ? 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-800/70' : 'bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:bg-slate-300 dark:hover:bg-slate-600')
                                      }`}
                                  >
                                      {filter.label} 
                                      <span className={`ml-2 inline-block rounded-full px-2 py-0.5 text-xs font-mono ${
                                          isActive ? 'bg-white/20' : (isHighlight ? 'bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200' : 'bg-slate-300 dark:bg-slate-600 text-slate-700 dark:text-slate-200')
                                      }`}>{filter.count}</span>
                                  </button>
                                  )
                              })}
                          </div>
                      </div>
                      
                      <div>
                          {/* Cookies Section */}
                           <div className="pt-2">
                              <h5 className="px-6 py-2 font-bold text-lg text-[var(--text-headings)]">Cookies ({activeFilter === FilterCategory.ALL ? result.cookies.length : filteredData.cookies.length})</h5>
                              {filteredData.cookies.length > 0 ? (
                                  <div className="overflow-x-auto">
                                      <table className="min-w-full divide-y divide-[var(--border-primary)]">
                                          <thead className="bg-[var(--bg-tertiary)]/50"><tr className="text-left text-xs font-bold text-[var(--text-primary)] uppercase tracking-wider">
                                              <th scope="col" className="px-6 py-3">Compliance Status</th>
                                              <th scope="col" className="px-6 py-3">Cookie Name</th>
                                              <th scope="col" className="px-6 py-3">Provider</th>
                                              <th scope="col" className="px-6 py-3">Category</th>
                                              <th scope="col" className="px-6 py-3">Party</th>
                                              <th scope="col" className="px-6 py-3">Expiry</th>
                                          </tr></thead>
                                          <tbody className="bg-[var(--bg-secondary)] divide-y divide-[var(--border-primary)]">
                                          {filteredData.cookies.map((cookie: CookieInfo) => (
                                              <tr key={cookie.key} className="hover:bg-[var(--bg-tertiary)]/60 transition-colors">
                                                  <td className="px-6 py-4"><ConsentStatus status={cookie.complianceStatus} category={cookie.category} /></td>
                                                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-[var(--text-headings)]">{cookie.name}</td>
                                                  <td className="px-6 py-4 whitespace-nowrap text-sm text-[var(--text-primary)]">{cookie.provider}</td>
                                                  <td className="px-6 py-4"><CategoryBadge category={cookie.category} /></td>
                                                  <td className="px-6 py-4"><span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${cookie.party === 'First' ? 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-300' : 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-300'}`}>{cookie.party} Party</span></td>
                                                  <td className="px-6 py-4 whitespace-nowrap text-sm text-[var(--text-primary)]">{cookie.expiry}</td>
                                              </tr>
                                          ))}
                                          </tbody>
                                      </table>
                                  </div>
                              ) : (
                                  <div className="text-center py-8 px-6">
                                      <p className="text-[var(--text-primary)]">{`There are no cookies matching the "${activeFilter}" filter.`}</p>
                                  </div>
                              )}
                          </div>

                          {/* Trackers Section */}
                          <div className="border-t border-[var(--border-primary)] pt-2 mt-4">
                            <h5 className="px-6 py-2 font-bold text-lg text-[var(--text-headings)]">Trackers ({activeFilter === FilterCategory.ALL ? result.trackers.length : filteredData.trackers.length})</h5>
                              {filteredData.trackers.length > 0 ? (
                                  <div className="overflow-x-auto">
                                      <table className="min-w-full divide-y divide-[var(--border-primary)]">
                                          <thead className="bg-[var(--bg-tertiary)]/50"><tr className="text-left text-xs font-bold text-[var(--text-primary)] uppercase tracking-wider">
                                              <th scope="col" className="px-6 py-3">Compliance Status</th>
                                              <th scope="col" className="px-6 py-3">Tracker Provider</th>
                                              <th scope="col" className="px-6 py-3">Category</th>
                                              <th scope="col" className="px-6 py-3 min-w-[300px]">Full URL</th>
                                          </tr></thead>
                                          <tbody className="bg-[var(--bg-secondary)] divide-y divide-[var(--border-primary)]">
                                          {filteredData.trackers.map((tracker: TrackerInfo) => (
                                              <tr key={tracker.key} className="hover:bg-[var(--bg-tertiary)]/60 transition-colors">
                                                  <td className="px-6 py-4"><ConsentStatus status={tracker.complianceStatus} category={tracker.category} /></td>
                                                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-[var(--text-headings)]">{tracker.provider}</td>
                                                  <td className="px-6 py-4"><CategoryBadge category={tracker.category} /></td>
                                                  <td className="px-6 py-4 text-sm text-[var(--text-primary)] font-mono break-all">{tracker.url}</td>
                                              </tr>
                                          ))}
                                          </tbody>
                                      </table>
                                  </div>
                              ) : (
                                  <div className="text-center py-8 px-6">
                                      <p className="text-[var(--text-primary)]">{`There are no trackers matching the "${activeFilter}" filter.`}</p>
                                  </div>
                              )}
                          </div>
                      </div>
                  </div>
              </div>
              <div className="lg:col-span-1 space-y-8">
                  <WebsiteScreenshot base64={result.screenshotBase64} url={scannedUrl} />
                  <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm p-5">
                      <h4 className="text-xl font-bold text-[var(--text-headings)] mb-2">Technology Categories</h4>
                      <TechPieChart items={[...result.cookies, ...result.trackers]} />
                  </div>
                  <ComplianceCard title="GDPR" data={result.compliance.gdpr} />
                  <ComplianceCard title="CCPA" data={result.compliance.ccpa} />
              </div>
          </div>
        </div>
      </div>
    </>
  );
};
