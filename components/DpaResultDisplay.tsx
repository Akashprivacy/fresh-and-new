
import React, { useState, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { DpaAnalysisResult, DpaPerspective, RiskLevel, DpaClauseAnalysis } from '../types';
import { AlertOctagonIcon, CheckCircleIcon, ShieldExclamationIcon, LightbulbIcon } from './Icons';

const getRiskStyle = (riskLevel: RiskLevel) => {
    switch (riskLevel) {
        case 'Critical': return { color: 'text-red-600 dark:text-red-400', borderColor: 'border-red-500', bgColor: 'bg-red-50 dark:bg-red-900/20', icon: <ShieldExclamationIcon className="h-6 w-6" />, chartFill: 'hsl(0, 72%, 51%)' };
        case 'High': return { color: 'text-orange-600 dark:text-orange-400', borderColor: 'border-orange-500', bgColor: 'bg-orange-50 dark:bg-orange-900/20', icon: <AlertOctagonIcon className="h-6 w-6" />, chartFill: 'hsl(30, 90%, 55%)' };
        case 'Medium': return { color: 'text-yellow-600 dark:text-yellow-400', borderColor: 'border-yellow-500', bgColor: 'bg-yellow-50 dark:bg-yellow-900/20', icon: <AlertOctagonIcon className="h-6 w-6" />, chartFill: 'hsl(45, 90%, 55%)' };
        case 'Low': return { color: 'text-green-600 dark:text-green-400', borderColor: 'border-green-500', bgColor: 'bg-green-50 dark:bg-green-900/20', icon: <CheckCircleIcon className="h-6 w-6" />, chartFill: 'hsl(140, 70%, 45%)' };
        default: return { color: 'text-slate-600 dark:text-slate-400', borderColor: 'border-slate-400', bgColor: 'bg-slate-100 dark:bg-slate-800/50', icon: <CheckCircleIcon className="h-6 w-6" />, chartFill: 'hsl(220, 10%, 50%)' };
    }
};

const OverallRiskCard: React.FC<{ level: RiskLevel, summary: string }> = ({ level, summary }) => {
  const { color, borderColor, bgColor, icon } = getRiskStyle(level);
  return (
    <div className={`p-6 rounded-lg border ${borderColor} ${bgColor} flex items-start gap-4`}>
        <div className={`flex-shrink-0 ${color}`}>{icon}</div>
        <div>
            <h4 className={`text-lg font-bold ${color}`}>{level} Risk Profile</h4>
            <p className="mt-1 text-sm text-[var(--text-primary)]">{summary}</p>
        </div>
    </div>
  )
}

const RiskDistributionChart: React.FC<{ data: { name: string; count: number; fill: string }[] }> = ({ data }) => (
    <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontal={false} />
            <XAxis type="number" allowDecimals={false} stroke="var(--text-primary)" fontSize={12} />
            <YAxis type="category" dataKey="name" width={80} stroke="var(--text-primary)" fontSize={12} axisLine={false} tickLine={false} />
            <Tooltip
                cursor={{ fill: 'var(--bg-tertiary)' }}
                contentStyle={{
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-primary)',
                    color: 'var(--text-headings)',
                    borderRadius: '0.5rem'
                }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
            </Bar>
        </BarChart>
    </ResponsiveContainer>
);


const ClauseAnalysisCard: React.FC<{ clause: DpaClauseAnalysis }> = ({ clause }) => {
  const { borderColor } = getRiskStyle(clause.riskLevel);
  return (
    <div className={`bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm overflow-hidden border-l-4 ${borderColor}`}>
      <div className="p-5 border-b border-[var(--border-primary)]">
        <div className="flex justify-between items-center">
            <h4 className="text-lg font-bold text-[var(--text-headings)]">{clause.clause}</h4>
            <span className={`inline-flex items-center gap-x-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${getRiskStyle(clause.riskLevel).bgColor} ${getRiskStyle(clause.riskLevel).color}`}>
                {clause.riskLevel} Risk
            </span>
        </div>
      </div>
      <div className="p-5 space-y-4">
        <div>
          <h5 className="font-semibold text-[var(--text-headings)] text-sm">Summary</h5>
          <p className="text-[var(--text-primary)] text-sm mt-1">{clause.summary}</p>
        </div>
        <div className="p-4 rounded-md bg-orange-50 dark:bg-orange-900/20 border border-orange-500/20">
          <h5 className="font-semibold text-orange-800 dark:text-orange-300 text-sm">Risk Analysis</h5>
          <p className="text-orange-700 dark:text-orange-300/90 text-sm mt-1">{clause.risk}</p>
        </div>
        <div className="p-4 rounded-md bg-green-50 dark:bg-green-900/20 border border-green-500/20">
          <h5 className="font-semibold text-green-800 dark:text-green-300 text-sm">Remediation Plan</h5>
          <p className="text-green-700 dark:text-green-300/90 text-sm mt-1">{clause.recommendation}</p>
        </div>
         {clause.negotiationTip && (
           <div className="p-4 rounded-md bg-blue-50 dark:bg-blue-900/20 border border-blue-500/20 flex items-start gap-3">
              <LightbulbIcon className="h-5 w-5 flex-shrink-0 text-blue-600 dark:text-blue-300 mt-0.5"/>
              <div>
                <h5 className="font-semibold text-blue-800 dark:text-blue-300 text-sm">Negotiation Tip</h5>
                <p className="text-blue-700 dark:text-blue-300/90 text-sm mt-1">{clause.negotiationTip}</p>
              </div>
          </div>
        )}
      </div>
    </div>
  )
}

const RiskFilterButton: React.FC<{
    risk: "All" | RiskLevel;
    count: number;
    activeFilter: string;
    setActiveFilter: (risk: "All" | RiskLevel) => void;
}> = ({ risk, count, activeFilter, setActiveFilter }) => {
    const isActive = activeFilter === risk;
    const baseStyle = "px-4 py-2 text-sm font-semibold rounded-full transition-colors duration-150 flex items-center";
    let style = "";

    if (isActive) {
        style = 'bg-brand-blue text-white shadow-sm';
    } else {
        style = 'bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:bg-slate-300 dark:hover:bg-slate-600';
    }

    if (risk === 'Critical' || risk === 'High') {
        if (isActive) style = 'bg-red-600 text-white shadow-sm';
        else style = 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-800/70';
    } else if (risk === 'Medium') {
        if (isActive) style = 'bg-yellow-500 text-white shadow-sm';
        else style = 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300 hover:bg-yellow-200 dark:hover:bg-yellow-800/70';
    }
    
    return (
        <button onClick={() => setActiveFilter(risk)} className={`${baseStyle} ${style}`}>
            {risk}
            <span className={`ml-2 inline-block rounded-full px-2 py-0.5 text-xs font-mono ${isActive ? 'bg-white/20' : 'bg-slate-300 dark:bg-slate-600 text-slate-700 dark:text-slate-200'}`}>
                {count}
            </span>
        </button>
    );
};

export const DpaResultDisplay: React.FC<{ result: DpaAnalysisResult; perspective: DpaPerspective }> = ({ result, perspective }) => {
  const perspectiveText = perspective === 'controller' ? 'Data Controller' : 'Data Processor';
  const [activeFilter, setActiveFilter] = useState<"All" | RiskLevel>('All');

  const riskCounts = useMemo(() => {
    return result.analysis.reduce((acc, clause) => {
        const level = clause.riskLevel || 'Unknown';
        acc[level] = (acc[level] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);
  }, [result.analysis]);

  const chartData = useMemo(() => {
    const order: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low'];
    return order
        .filter(level => riskCounts[level] > 0)
        .map(level => ({
            name: level,
            count: riskCounts[level],
            fill: getRiskStyle(level).chartFill,
        }));
  }, [riskCounts]);
  
  const filteredClauses = useMemo(() => {
      if (activeFilter === 'All') return result.analysis;
      return result.analysis.filter(clause => clause.riskLevel === activeFilter);
  }, [result.analysis, activeFilter]);

  return (
    <div className="max-w-5xl mx-auto animate-fade-in-up">
      <div className="mb-8 text-center">
        <h3 className="text-2xl font-bold text-[var(--text-headings)]">DPA Analysis Dashboard</h3>
        <p className="text-[var(--text-primary)] mt-1">
          Analyzed from the perspective of a <span className="font-semibold text-brand-blue">{perspectiveText}</span>.
        </p>
      </div>
      
      <div className="space-y-8">
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            <div className="lg:col-span-3">
                <OverallRiskCard level={result.overallRisk.level} summary={result.overallRisk.summary} />
            </div>
            <div className="lg:col-span-2 bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] p-5">
                <h4 className="text-md font-bold text-[var(--text-headings)] mb-2 text-center">Risk Distribution</h4>
                {chartData.length > 0 ? (
                    <RiskDistributionChart data={chartData} />
                ) : (
                    <div className="flex items-center justify-center h-full text-sm text-[var(--text-primary)]">
                        No risks identified in clauses.
                    </div>
                )}
            </div>
        </div>

        <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] p-5">
            <h4 className="text-lg font-bold text-[var(--text-headings)] mb-4">Clause Analysis & Remediation</h4>
             <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border-primary)] pb-4 mb-6">
                <RiskFilterButton risk="All" count={result.analysis.length} activeFilter={activeFilter} setActiveFilter={setActiveFilter} />
                {(['Critical', 'High', 'Medium', 'Low'] as RiskLevel[]).map(risk => 
                    riskCounts[risk] > 0 && (
                        <RiskFilterButton key={risk} risk={risk} count={riskCounts[risk]} activeFilter={activeFilter} setActiveFilter={setActiveFilter} />
                    )
                )}
            </div>

            <div className="space-y-6">
                {filteredClauses.map((clause, index) => (
                    <ClauseAnalysisCard key={index} clause={clause} />
                ))}
            </div>
             {filteredClauses.length === 0 && activeFilter !== 'All' && (
                <div className="text-center py-10 text-[var(--text-primary)]">
                    <p>No clauses found with a "{activeFilter}" risk level.</p>
                </div>
            )}
        </div>
      </div>
    </div>
  );
};
