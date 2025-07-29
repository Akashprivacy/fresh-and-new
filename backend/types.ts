
// This file defines types shared within the backend service.

export enum CookieCategory {
  NECESSARY = 'Necessary',
  ANALYTICS = 'Analytics',
  MARKETING = 'Marketing',
  FUNCTIONAL = 'Functional',
  UNKNOWN = 'Unknown',
}

export type ComplianceStatus = 'Compliant' | 'Pre-Consent Violation' | 'Post-Rejection Violation' | 'Unknown';
export type CookieParty = 'First' | 'Third';
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Unknown';


export interface CookieInfo {
  key: string;
  name: string;
  provider: string; 
  category: CookieCategory | string;
  expiry: string;
  purpose: string;
  party: CookieParty;
  isHttpOnly: boolean;
  isSecure: boolean;
  complianceStatus: ComplianceStatus;
}

export interface TrackerInfo {
    key: string;
    url: string;
    provider: string;
    category: CookieCategory | string;
    complianceStatus: ComplianceStatus;
}

export interface ComplianceInfo {
    riskLevel: RiskLevel;
    assessment: string;
}

export interface ScanResultData {
  cookies: CookieInfo[];
  trackers: TrackerInfo[];
  screenshotBase64: string;
  compliance: {
    gdpr: ComplianceInfo;
    ccpa: ComplianceInfo;
  };
}


// --- DPA Reviewer Types ---
export type DpaPerspective = 'controller' | 'processor';

export interface DpaClauseAnalysis {
  clause: string;
  summary: string;
  risk: string;
  riskLevel: RiskLevel;
  recommendation: string;
  negotiationTip: string;
}

export interface DpaAnalysisResult {
  overallRisk: {
    level: RiskLevel;
    summary: string;
  };
  analysis: DpaClauseAnalysis[];
}

// --- Vulnerability Scanner Types ---
export interface VulnerabilityInfo {
    title: string;
    description: string;
    risk: RiskLevel;
    remediation: string;
    owaspCategory: string;
}

export interface VulnerabilityReport {
    overallScore: number;
    riskLevel: RiskLevel;
    summary: string;
    vulnerabilities: VulnerabilityInfo[];
}

// --- Gemini Analysis Types ---
export interface CookieAnalysis {
    key: string;
    category: CookieCategory | string;
    purpose: string;
    complianceStatus: ComplianceStatus;
}

export interface TrackerAnalysis {
    key: string;
    category: CookieCategory | string;
    complianceStatus: ComplianceStatus;
}

export interface GeminiScanAnalysis {
    cookies: CookieAnalysis[];
    trackers: TrackerAnalysis[];
    compliance: {
      gdpr: ComplianceInfo;
      ccpa: ComplianceInfo;
    };
}
