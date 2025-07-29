
import React from 'react';

interface IconProps {
  className?: string;
}

export const CookieCareLogo: React.FC<IconProps> = ({ className }) => (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M12 7v5" />
        <path d="m10 9 2 2 2-2" />
    </svg>
);

export const RandstadDigitalLogo: React.FC<IconProps> = ({ className }) => (
    <svg className={className} viewBox="0 0 76 12" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M16.11 0.160156H19.41L16.03 4.49016L19.53 9.00016H16.19L14.07 6.10016L11.95 9.00016H8.65L11.95 4.49016L8.49001 0.160156H11.83L14.07 3.17016L16.11 0.160156Z" />
        <path d="M0 9.74023V11.8002H7.53V9.74023H4.8V2.00023H2.76V9.74023H0Z" />
        <path d="M8.7002 2.00023V11.8002H10.7402V4.08023L13.8602 9.32023L13.9202 9.44023V11.8002H15.9602V2.00023H13.9202L10.7702 7.32023L10.7402 7.18023V2.00023H8.7002Z" />
        <path d="M17.1595 2H19.2195V11.8H17.1595V2Z" />
        <path d="M20.3998 2H28.0198V3.98H22.4198V5.8H27.5398V7.78H22.4198V9.82H28.0198V11.8H20.3998V2Z" />
        <path d="M29.2801 2H31.3201V11.8H29.2801V2Z" />
        <path d="M32.5802 2H34.6202L37.8602 8.64023L37.9202 8.78023V2.00023H39.9602V11.8002H37.9202L34.6202 5.14023L34.5002 4.98023V11.8002H32.5802V2.00023Z" />
        <path d="M41.22 2H48.84V3.98H43.26V5.8H48.36V7.78H43.26V9.82H48.84V11.8H41.22V2Z" />
        <path d="M69.2177 4.6001C69.2177 3.1401 67.9777 2.0001 66.5177 2.0001C65.0577 2.0001 63.8177 3.1401 63.8177 4.6001C63.8177 6.0601 65.0577 7.2001 66.5177 7.2001C67.9777 7.2001 69.2177 6.0601 69.2177 4.6001ZM67.0177 4.6001C67.0177 4.2201 66.8077 3.9801 66.5177 3.9801C66.2277 3.9801 65.9877 4.2201 65.9877 4.6001C65.9877 4.9801 66.2277 5.2201 66.5177 5.2201C66.8077 5.2201 67.0177 4.9801 67.0177 4.6001Z" />
        <path d="M50.2793 2H52.3593V11.8H50.2793V2Z" />
        <path d="M53.4792 2H55.5192V11.8H53.4792V2Z" />
        <path d="M70.0596 2H72.0996V11.8H70.0596V2Z" />
        <path d="M69.2795 11.8V8.74023L66.5795 11.8002H65.2595L63.7795 8.74023V11.8002H61.7395V2.00023H64.0595L66.5495 7.02023L72.8401 2.00023H75.1201V11.8002H73.0801V2.00023L69.2795 11.8Z" />
    </svg>
);

export const AlertTriangleIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
    </svg>
);

export const AlertOctagonIcon: React.FC<IconProps> = ({ className }) => (
  <svg className={className} fill="currentColor" strokeWidth="1" stroke="currentColor" viewBox="0 0 24 24">
    <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon>
    <line fill="none" x1="12" y1="8" x2="12" y2="12"></line>
    <line fill="none" x1="12" y1="16" x2="12.01" y2="16"></line>
  </svg>
);

export const SearchIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
    </svg>
);

export const CheckCircleIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
    </svg>
);

export const AnalyticsIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 8v8m-4-5v5m-4-2v2m-2 4h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
    </svg>
);

export const MarketingIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.148-6.136a1.76 1.76 0 011.176-2.373l5.485-1.948a1.76 1.76 0 012.373 1.176l.636 1.817M11 5.882L15.24 4.14a1.76 1.76 0 012.373 1.176l.636 1.817m-6.255 0l-1.818-5.193m-3.595.636l1.818 5.193"></path>
    </svg>
);

export const FunctionalIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
    </svg>
);

export const NecessaryIcon: React.FC<IconProps> = ({ className }) => (
  <svg className={className} fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
    <path d="M21.73 18.27l-4.24-4.24m0 0a2.5 2.5 0 10-3.54-3.54l-4.24-4.24-1.77 1.77 4.24 4.24 3.54 3.54 4.24 4.24 1.77-1.77zM4.27 5.73l1.41 1.41"></path>
    <path d="M2 12h3m8.66-6.66l1.41-1.41M12 2v3m6.66 1.66l-1.41 1.41"></path>
  </svg>
);

export const UnknownIcon: React.FC<IconProps> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
    </svg>
);

export const FileTextIcon: React.FC<IconProps> = ({ className }) => (
  <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
    <polyline points="14 2 14 8 20 8"></polyline>
    <line x1="16" y1="13" x2="8" y2="13"></line>
    <line x1="16" y1="17" x2="8" y2="17"></line>
    <polyline points="10 9 9 9 8 9"></polyline>
  </svg>
);

export const CodeBracketIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
);

export const SunIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className={className}>
        <path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.106a.75.75 0 010 1.06l-1.591 1.59a.75.75 0 11-1.06-1.06l1.59-1.59a.75.75 0 011.06 0zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5h2.25a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 01-1.06 0l-1.59-1.59a.75.75 0 111.06-1.06l1.59 1.59a.75.75 0 010 1.06zM12 21.75a.75.75 0 01-.75-.75v-2.25a.75.75 0 011.5 0v2.25a.75.75 0 01-.75-.75zM5.106 17.834a.75.75 0 010-1.06l1.59-1.59a.75.75 0 111.06 1.06l-1.59 1.59a.75.75 0 01-1.06 0zM3 12a.75.75 0 01.75-.75h2.25a.75.75 0 010 1.5H3.75A.75.75 0 013 12zM6.106 5.106a.75.75 0 011.06 0l1.59 1.59a.75.75 0 01-1.06 1.06l-1.59-1.59a.75.75 0 010-1.06z" />
    </svg>
);

export const MoonIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className={className}>
        <path fillRule="evenodd" d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 004.463-.948.75.75 0 01.981.635A11.25 11.25 0 0112 21a11.25 11.25 0 01-11.25-11.25c0-4.336 2.1-8.217 5.528-10.472a.75.75 0 01.819.162z" clipRule="evenodd" />
    </svg>
);

export const ShieldExclamationIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
);

export const ShieldCheckIcon: React.FC<IconProps> = ({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className={className}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4" />
  </svg>
);

export const BanIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24" strokeWidth={1.5} stroke="white" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
);

export const DocumentTextIcon: React.FC<IconProps> = ({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m.75 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
  </svg>
);

export const LightbulbIcon: React.FC<IconProps> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 001.5-11.641a6.01 6.01 0 00-1.5-1.059m-1.5 12.7v-5.25m0 0a6.01 6.01 0 01-1.5-11.641a6.01 6.01 0 011.5-1.059M12 18.75a.75.75 0 01.75.75v.008c0 .414-.336.75-.75.75h-1.5a.75.75 0 01-.75-.75v-.008c0-.414.336-.75.75-.75h1.5z" />
    </svg>
);
