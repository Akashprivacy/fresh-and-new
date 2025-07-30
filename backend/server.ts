
import express from 'express';
import puppeteer from 'puppeteer-core';
import type { Cookie, Page, Frame, Browser, BrowserContext, HTTPResponse } from 'puppeteer-core';
import chromium from '@sparticuz/chromium';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { CookieCategory, type CookieInfo, type ScanResultData, type TrackerInfo, type DpaAnalysisResult, type DpaPerspective, type VulnerabilityReport, type GeminiScanAnalysis } from './types.js';

dotenv.config();

const app: express.Application = express();
const port = process.env.PORT || 3001;

// --- DEFINITIVE, PRODUCTION-READY CORS SETUP ---
const allowedOrigins = [
  // Hardcode the Vercel production URL to guarantee it's always allowed.
  'https://cookie-care.vercel.app', 
  
  // Also include the URL from environment variables for flexibility.
  process.env.FRONTEND_URL, 
  
  // Include common local development URLs.
  'http://localhost:3000',
  'http://localhost:5173',
  'http://12-7.0.0.1:5500'
].filter(Boolean); // Removes any falsy values (like an unset process.env.FRONTEND_URL)

console.log(`[CORS] Allowed Origins configured: ${allowedOrigins.join(', ')}`);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, or server-to-server)
    if (!origin) {
      console.log('[CORS] Allowing request with no origin.');
      return callback(null, true);
    }
    
    // The pattern to match Vercel URLs for this project.
    // It allows the main production URL and any preview URLs like 'cookie-care-*.vercel.app'
    const vercelPattern = /^https:\/\/cookie-care.*\.vercel\.app$/;

    // Check if the incoming origin is on our static list OR if it's a valid Vercel URL.
    if (allowedOrigins.includes(origin) || vercelPattern.test(origin)) {
      console.log(`[CORS] Origin allowed: ${origin}`);
      return callback(null, true);
    }

    // If the origin is not on our list, block the request.
    const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
    console.error(`[CORS] Blocking request. ${msg}`);
    return callback(new Error(msg), false);
  },
};

// Use the CORS middleware for all requests. It handles preflight OPTIONS requests automatically.
app.use(cors(corsOptions));
// --- END OF CORS SETUP ---


app.use(express.json({ limit: '10mb' }));

if (!process.env.API_KEY) {
  console.error("FATAL ERROR: API_KEY environment variable is not set.");
  (process as any).exit(1);
}

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
const model = "gemini-2.5-flash";


// --- HELPER FUNCTIONS ---

/**
 * Executes a function with a retry mechanism for transient errors.
 * @param fn The async function to execute.
 * @param retries Number of retries.
 * @param delay Initial delay in ms, which will be doubled on each retry.
 * @returns The result of the function.
 */
async function withRetry<T>(fn: () => Promise<T>, retries = 3, delay = 2000): Promise<T> {
  let lastError: Error | undefined;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;
      const isTransientError = error.message?.includes('503') || error.message?.includes('overloaded') || error.message?.includes('UNAVAILABLE') || error.message?.includes('429');
      
      if (isTransientError && i < retries - 1) {
        console.warn(`[RETRY] Transient error detected (Attempt ${i + 1}/${retries}). Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2; // Exponential backoff
      } else {
        console.error(`[RETRY] Unrecoverable error after ${i + 1} attempts.`);
        throw error;
      }
    }
  }
  throw lastError; // Should be unreachable but satisfies TypeScript
}


/**
 * Extracts a JSON object from a string, handling cases where it's wrapped in markdown or has surrounding text.
 * @param text The string potentially containing a JSON object.
 * @returns The extracted JSON string.
 */
function extractJson(text: string): string {
    // Look for a JSON block within markdown, making the 'json' language specifier optional.
    const markdownMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    if (markdownMatch && markdownMatch[1]) {
        return markdownMatch[1].trim();
    }

    // If no markdown, find the first '{' or '[' and the last '}' or ']'
    // This is a greedy approach to catch JSON embedded in conversational text.
    const firstBracket = text.indexOf('{');
    const firstSquare = text.indexOf('[');
    
    let startIndex = -1;
    
    if (firstBracket === -1 && firstSquare === -1) {
        // No JSON object found at all. Return original text to let JSON.parse fail.
        return text;
    }
    
    if (firstBracket === -1) {
        startIndex = firstSquare;
    } else if (firstSquare === -1) {
        startIndex = firstBracket;
    } else {
        startIndex = Math.min(firstBracket, firstSquare);
    }

    const startChar = text[startIndex];
    const endChar = startChar === '{' ? '}' : ']';
    
    const lastBracket = text.lastIndexOf(endChar);
    
    if (lastBracket > startIndex) {
        return text.substring(startIndex, lastBracket + 1);
    }
    
    return text;
}


const knownTrackerDomains = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'facebook.net', 'fbcdn.net',
    'analytics.yahoo.com', 'linkedin.com/li/sso', 'bing.com', 'hotjar.com', 'hubspot.com',
    'amazon-adsystem.com', 'criteo.com', 'adroll.com', 'outbrain.com', 'taboola.com',
    'scorecardresearch.com', 'quantserve.com', 'adobedtm.com', 'demdex.net', 'matomo.org',
    'mixpanel.com', 'segment.com', 'vwo.com', 'optimizely.com', 'crazyegg.com', 'yandex.ru'
];

function getDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (e) {
    return '';
  }
}

function getCookieInfo(cookie: Cookie, siteDomain: string): Omit<CookieInfo, 'purpose' | 'category' | 'complianceStatus'> {
    const expiry = cookie.expires === -1 ? 'Session' : new Date(cookie.expires * 1000).toLocaleString();
    const provider = getDomain(cookie.domain) || siteDomain;
    return {
        key: `${cookie.name}:${cookie.domain}`,
        name: cookie.name,
        provider,
        party: getDomain(cookie.domain) === siteDomain ? 'First' : 'Third',
        expiry,
        isHttpOnly: cookie.httpOnly,
        isSecure: cookie.secure,
    };
}

function getTrackerInfo(requestUrl: string): Omit<TrackerInfo, 'category' | 'complianceStatus'>{
    const provider = getDomain(requestUrl) || 'Unknown';
    return {
        key: requestUrl,
        url: requestUrl,
        provider,
    };
}


// --- GEMINI ANALYSIS FUNCTIONS ---

async function analyzeWithGemini(
    url: string,
    preConsentCookies: Omit<CookieInfo, 'purpose' | 'category' | 'complianceStatus'>[],
    preConsentTrackers: Omit<TrackerInfo, 'category' | 'complianceStatus'>[],
    postRejectionCookies: Omit<CookieInfo, 'purpose' | 'category' | 'complianceStatus'>[],
    postRejectionTrackers: Omit<TrackerInfo, 'category' | 'complianceStatus'>[],
    finalCookies: Omit<CookieInfo, 'purpose' | 'category' | 'complianceStatus'>[],
    finalTrackers: Omit<TrackerInfo, 'category' | 'complianceStatus'>[]
): Promise<GeminiScanAnalysis> {
    const systemInstruction = `
You are a world-class expert in web privacy, GDPR, and CCPA compliance. Your task is to analyze cookie and tracker data from a three-stage website scan and provide a structured JSON response.

**Analysis Rules:**

1.  **Compliance Status Logic (Crucial):**
    *   **'Pre-Consent Violation':** A non-essential cookie/tracker found in the 'preConsent' lists.
    *   **'Post-Rejection Violation':** A non-essential cookie/tracker found in the 'postRejection' lists.
    *   **'Compliant':**
        *   Any cookie/tracker categorized as 'Necessary'.
        *   Any non-essential cookie/tracker that is *only* present in the 'final' lists (meaning it was loaded correctly after consent).
    *   **'Unknown':** If the status cannot be determined.

2.  **Categorization:** Assign one of these categories: 'Necessary', 'Analytics', 'Marketing', 'Functional', 'Unknown'.
    *   'Necessary' cookies are vital for basic site functions (e.g., session IDs, load balancing, security tokens).
    *   'Analytics' cookies track user behavior and statistics.
    *   'Marketing' cookies are for advertising, retargeting, and user profiling.
    *   'Functional' cookies remember user choices (e.g., language, region).

3.  **Risk Assessment:** For GDPR and CCPA, provide a 'riskLevel' ('Low', 'Medium', 'High', 'Critical') and a concise 'assessment' summarizing the findings.
    *   **Low Risk:** Only compliant 'Necessary' cookies found.
    *   **Medium Risk:** Compliant non-essential cookies are present, or minor non-compliance (e.g., one or two post-rejection trackers).
    *   **High Risk:** Multiple post-rejection violations or a few pre-consent violations.
    *   **Critical Risk:** Widespread pre-consent violations, especially involving sensitive data or aggressive marketing trackers.

4.  **Purpose:** Provide a brief, clear 'purpose' for each cookie.

5.  **JSON Output:** The final output must be a single, valid JSON object matching the provided schema. Do not include any text outside the JSON block.
`;

    const prompt = `
Analyze the following data from a scan of ${url} and return the analysis as a JSON object.

**Scan Data:**

*   **Pre-Consent (before any interaction):**
    *   Cookies: ${JSON.stringify(preConsentCookies.map(c=>c.name))}
    *   Trackers: ${JSON.stringify(preConsentTrackers.map(t=>t.provider))}

*   **Post-Rejection (after user rejected consent):**
    *   Cookies: ${JSON.stringify(postRejectionCookies.map(c=>c.name))}
    *   Trackers: ${JSON.stringify(postRejectionTrackers.map(t=>t.provider))}

*   **Final State (after user accepted consent):**
    *   Cookies: ${JSON.stringify(finalCookies)}
    *   Trackers: ${JSON.stringify(finalTrackers)}

Based on these lists, perform the analysis as described in your instructions and provide the JSON output.
`;
    
    const responseSchema = {
        type: Type.OBJECT,
        properties: {
            cookies: {
                type: Type.ARRAY,
                items: {
                    type: Type.OBJECT,
                    properties: {
                        key: { type: Type.STRING },
                        category: { type: Type.STRING, enum: Object.values(CookieCategory) },
                        purpose: { type: Type.STRING },
                        complianceStatus: { type: Type.STRING, enum: ['Compliant', 'Pre-Consent Violation', 'Post-Rejection Violation', 'Unknown'] },
                    }
                }
            },
            trackers: {
                type: Type.ARRAY,
                items: {
                    type: Type.OBJECT,
                    properties: {
                        key: { type: Type.STRING },
                        category: { type: Type.STRING, enum: Object.values(CookieCategory) },
                        complianceStatus: { type: Type.STRING, enum: ['Compliant', 'Pre-Consent Violation', 'Post-Rejection Violation', 'Unknown'] },
                    }
                }
            },
            compliance: {
                type: Type.OBJECT,
                properties: {
                    gdpr: { 
                        type: Type.OBJECT, 
                        properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } } 
                    },
                    ccpa: { 
                        type: Type.OBJECT, 
                        properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } } 
                    }
                }
            }
        }
    };

    const result = await withRetry(async () => {
        const genAIResponse = await ai.models.generateContent({
            model: model,
            contents: [{ parts: [{ text: prompt }] }],
            config: {
                systemInstruction: systemInstruction,
                responseMimeType: "application/json",
                responseSchema: responseSchema,
                temperature: 0.1
            }
        });
        return genAIResponse;
    });
    
    const jsonText = extractJson(result.text);
    return JSON.parse(jsonText) as GeminiScanAnalysis;
}

async function analyzeDpaWithGemini(dpaText: string, perspective: DpaPerspective): Promise<DpaAnalysisResult> {
  const systemInstruction = `
You are a legal expert specializing in data privacy agreements (DPAs) like those under GDPR. Analyze the provided DPA text from the perspective of a ${perspective}. Your analysis must be structured, practical, and risk-focused.

**Analysis Rules:**

1.  **Perspective is Key:**
    *   If **Controller**, focus on risks where the Processor has too much control, vague responsibilities, or insufficient security commitments.
    *   If **Processor**, focus on risks where the Controller imposes unreasonable obligations, liability is unlimited, or instructions are ambiguous.

2.  **Clause Identification:** Identify key clauses (e.g., 'Data Security', 'Sub-processors', 'Audits', 'Liability', 'Data Deletion').

3.  **Risk Level:** Assign a 'riskLevel' ('Low', 'Medium', 'High', 'Critical') to each clause.
    *   **Low:** Standard, fair, and clear clause.
    *   **Medium:** Vague language or minor imbalance.
    *   **High:** Significant imbalance of obligations or clear risk exposure.
    *   **Critical:** Unacceptable terms, unlimited liability, or non-compliance with major regulations.

4.  **Practical Advice:** For each clause, provide:
    *   'summary': A plain-language explanation of the clause.
    *   'risk': A clear description of the specific risk from your perspective.
    *   'recommendation': A concrete suggestion for how to mitigate the risk (e.g., "Propose adding a specific timeframe for breach notification...").
    *   'negotiationTip': A practical tip for discussing the change (e.g., "Frame this as a request for clarity to ensure both parties are protected.").

5.  **Overall Assessment:** Provide an 'overallRisk' object with a 'level' and a 'summary' of the entire DPA's risk profile.

6.  **JSON Output:** The final output must be a single, valid JSON object matching the provided schema. Do not include any text outside the JSON block.
`;

    const prompt = `
Analyze the following DPA text from the perspective of a **${perspective}**.

**DPA Text:**
\`\`\`
${dpaText}
\`\`\`

Based on this text, perform the analysis as described in your instructions and provide the JSON output.
`;

    const responseSchema = {
        type: Type.OBJECT,
        properties: {
            overallRisk: {
                type: Type.OBJECT,
                properties: {
                    level: { type: Type.STRING, enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
                    summary: { type: Type.STRING },
                },
            },
            analysis: {
                type: Type.ARRAY,
                items: {
                    type: Type.OBJECT,
                    properties: {
                        clause: { type: Type.STRING },
                        summary: { type: Type.STRING },
                        risk: { type: Type.STRING },
                        riskLevel: { type: Type.STRING, enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
                        recommendation: { type: Type.STRING },
                        negotiationTip: { type: Type.STRING },
                    },
                },
            },
        },
    };
    
    const result = await withRetry(async () => {
        const genAIResponse = await ai.models.generateContent({
            model: model,
            contents: [{ parts: [{ text: prompt }] }],
            config: {
                systemInstruction: systemInstruction,
                responseMimeType: "application/json",
                responseSchema: responseSchema,
                temperature: 0.2
            }
        });
        return genAIResponse;
    });

    const jsonText = extractJson(result.text);
    return JSON.parse(jsonText) as DpaAnalysisResult;
}

async function analyzeVulnerabilitiesWithGemini(url: string, pageSource: string, headers: Record<string, string>): Promise<VulnerabilityReport> {
    const systemInstruction = `
You are a senior cybersecurity analyst specializing in web application security. Your task is to perform a passive, non-intrusive vulnerability scan based on the provided page source and HTTP headers.

**Analysis Rules:**

1.  **Passive Analysis Only:** Do not suggest any active scanning or testing. Your analysis is based *only* on the provided HTML source and headers.
2.  **Identify Common Vulnerabilities:** Check for indicators of common vulnerabilities like:
    *   **Security Headers:** Missing or misconfigured headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, etc.).
    *   **Information Exposure:** Sensitive information in comments, metadata, or scripts (e.g., API keys, internal paths, versions).
    *   **Outdated Libraries:** Look for common JS libraries and mention the *potential* risk if they are outdated (e.g., "Uses jQuery, ensure it's the latest version to avoid known CVEs.").
    *   **Insecure Form Handling:** \`action\` attributes pointing to HTTP endpoints, lack of CSRF tokens (mention this as a potential issue).
    *   **Mixed Content:** Loading scripts or resources over HTTP on an HTTPS page.
3.  **Structure and Detail:**
    *   'title': A clear, descriptive title for the vulnerability.
    *   'description': Explain what the vulnerability is and why it's a risk.
    *   'risk': Assign a 'risk' level ('Critical', 'High', 'Medium', 'Low', 'Informational'). Base this on potential impact.
    *   'remediation': Provide a clear, actionable remediation plan. Include code examples where appropriate.
    *   'owaspCategory': Link it to a relevant OWASP Top 10 category (e.g., 'A05:2021 - Security Misconfiguration').
4.  **Overall Assessment:** Provide an 'overallScore' (0-100, where 100 is excellent), a summary 'riskLevel', and a brief 'summary' of the site's security posture.
5.  **JSON Output:** The final output must be a single, valid JSON object matching the provided schema. Do not include any text outside the JSON block.
`;

    const prompt = `
Analyze the following data from a passive scan of ${url}.

**HTTP Headers:**
\`\`\`json
${JSON.stringify(headers, null, 2)}
\`\`\`

**Page Source (first 10000 chars):**
\`\`\`html
${pageSource.substring(0, 10000)}
\`\`\`

Based on this data, perform the analysis as described in your instructions and provide the JSON output. If no significant vulnerabilities are found, return an empty 'vulnerabilities' array and a high score.
`;
    
    const responseSchema = {
        type: Type.OBJECT,
        properties: {
            overallScore: { type: Type.INTEGER },
            riskLevel: { type: Type.STRING, enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
            summary: { type: Type.STRING },
            vulnerabilities: {
                type: Type.ARRAY,
                items: {
                    type: Type.OBJECT,
                    properties: {
                        title: { type: Type.STRING },
                        description: { type: Type.STRING },
                        risk: { type: Type.STRING, enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
                        remediation: { type: Type.STRING },
                        owaspCategory: { type: Type.STRING },
                    }
                }
            }
        }
    };
    
    const result = await withRetry(async () => {
        const genAIResponse = await ai.models.generateContent({
            model: model,
            contents: [{ parts: [{ text: prompt }] }],
            config: {
                systemInstruction: systemInstruction,
                responseMimeType: "application/json",
                responseSchema: responseSchema,
                temperature: 0.1
            }
        });
        return genAIResponse;
    });

    const jsonText = extractJson(result.text);
    return JSON.parse(jsonText) as VulnerabilityReport;
}


// --- API ENDPOINTS ---

interface ApiScanRequestBody {
  url: string;
}

app.post('/api/scan', async (req: express.Request<{}, {}, ApiScanRequestBody>, res: express.Response) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    console.log(`[SERVER] Received scan request for: ${url}`);
    
    let browser: Browser | null = null;
    try {
        console.log('[PUPPETEER] Launching new browser for this request.');
        browser = await puppeteer.launch({
            args: chromium.args,
            executablePath: await chromium.executablePath(),
            headless: 'new',
        });
        console.log('[PUPPETEER] Browser launched successfully.');

        const siteDomain = getDomain(url);
        const collectedTrackers = new Set<string>();
        const onResponse = (response: HTTPResponse) => {
            const requestUrl = response.url();
            if (knownTrackerDomains.some(domain => requestUrl.includes(domain)) && !requestUrl.startsWith('data:')) {
                collectedTrackers.add(requestUrl);
            }
        };
        
        const context = await browser.createBrowserContext();
        const page = (await context.pages())[0];
        await page.setViewport({ width: 1280, height: 800 });
        page.on('response', onResponse);

        // Stage 1: Pre-Consent
        console.log('[SCAN] Stage 1: Pre-Consent scan...');
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        await new Promise(r => setTimeout(r, 3000)); // Wait for dynamic scripts
        const preConsentRawCookies = await page.cookies();
        const preConsentTrackers = Array.from(collectedTrackers).map(getTrackerInfo);
        const screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });
        
        // Stage 2: Post-Rejection
        console.log('[SCAN] Stage 2: Post-Rejection scan...');
        collectedTrackers.clear();
        await page.reload({ waitUntil: 'networkidle2' });
        // This is a generic rejection simulation. It won't work for all banners.
        try {
          await page.evaluate(() => {
            const selectors = [
              '[id*="reject"]', '[class*="reject"]', '[id*="decline"]', '[class*="decline"]',
              'button ::-p-text(Reject all)', 'button ::-p-text(Decline all)', 'button ::-p-text(I refuse)'
            ];
            const rejectButton = document.querySelector(selectors.join(', '));
            if (rejectButton && (rejectButton as HTMLElement).click) {
              (rejectButton as HTMLElement).click();
            }
          });
          await new Promise(r => setTimeout(r, 2000));
        } catch(e) {
          console.warn("Could not find or click a reject button.");
        }
        const postRejectionRawCookies = await page.cookies();
        const postRejectionTrackers = Array.from(collectedTrackers).map(getTrackerInfo);

        // Stage 3: Final State (Accept all)
        console.log('[SCAN] Stage 3: Final state scan...');
        collectedTrackers.clear();
        await page.reload({ waitUntil: 'networkidle2' });
        try {
          await page.evaluate(() => {
            const selectors = [
              '[id*="accept"]', '[class*="accept"]', '[id*="allow"]', '[class*="allow"]',
              'button ::-p-text(Accept all)', 'button ::-p-text(Allow all)'
            ];
            const acceptButton = document.querySelector(selectors.join(', '));
            if (acceptButton && (acceptButton as HTMLElement).click) {
                (acceptButton as HTMLElement).click();
            }
          });
          await new Promise(r => setTimeout(r, 2000));
        } catch (e) {
            console.warn("Could not find or click an accept button.");
        }
        const finalRawCookies = await page.cookies();
        const finalTrackers = Array.from(collectedTrackers).map(getTrackerInfo);

        page.off('response', onResponse);
        await context.close();
        
        console.log('[AI] Analyzing data with Gemini...');
        const analysis = await analyzeWithGemini(
            url,
            preConsentRawCookies.map(c => getCookieInfo(c, siteDomain)),
            preConsentTrackers,
            postRejectionRawCookies.map(c => getCookieInfo(c, siteDomain)),
            postRejectionTrackers,
            finalRawCookies.map(c => getCookieInfo(c, siteDomain)),
            finalTrackers
        );

        const finalCookiesWithAnalysis = finalRawCookies.map(cookie => {
            const info = getCookieInfo(cookie, siteDomain);
            const cookieAnalysis = analysis.cookies.find(c => c.key === info.key);
            return { ...info, ...cookieAnalysis };
        });
        
        const finalTrackersWithAnalysis = finalTrackers.map(tracker => {
            const trackerAnalysis = analysis.trackers.find(t => t.key === tracker.key);
            return { ...tracker, ...trackerAnalysis };
        });

        const scanResult: ScanResultData = {
            cookies: finalCookiesWithAnalysis,
            trackers: finalTrackersWithAnalysis,
            screenshotBase64,
            compliance: analysis.compliance,
        };
        
        console.log('[SERVER] Scan complete. Sending results.');
        res.json(scanResult);

    } catch (error: any) {
        console.error('[SERVER] Scan failed:', error);
        res.status(500).json({ error: error.message || 'An unexpected error occurred during the scan.' });
    } finally {
        if (browser) {
            console.log('[PUPPETEER] Closing browser for this request.');
            await browser.close();
        }
    }
});

interface DpaReviewRequestBody {
  dpaText: string;
  perspective: DpaPerspective;
}

app.post('/api/review-dpa', async (req: express.Request<{}, {}, DpaReviewRequestBody>, res: express.Response) => {
    const { dpaText, perspective } = req.body;
    if (!dpaText || !perspective) {
        return res.status(400).json({ error: 'DPA text and perspective are required' });
    }

    console.log(`[SERVER] Received DPA review request. Perspective: ${perspective}`);
    
    try {
        const analysisResult = await analyzeDpaWithGemini(dpaText, perspective);
        console.log('[SERVER] DPA analysis complete. Sending results.');
        res.json(analysisResult);
    } catch (error: any) {
        console.error('[SERVER] DPA analysis failed:', error);
        res.status(500).json({ error: error.message || 'An unexpected error occurred during the DPA analysis.' });
    }
});

interface VulnerabilityScanBody {
    url: string;
}

app.post('/api/scan-vulnerability', async (req: express.Request<{}, {}, VulnerabilityScanBody>, res: express.Response) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    console.log(`[SERVER] Received vulnerability scan request for: ${url}`);
    
    let browser: Browser | null = null;
    try {
        console.log('[PUPPETEER] Launching new browser for this request.');
        browser = await puppeteer.launch({
            args: chromium.args,
            executablePath: await chromium.executablePath(),
            headless: 'new',
        });
        console.log('[PUPPETEER] Browser launched successfully.');
        
        const page = (await browser.pages())[0];
        await page.setBypassCSP(true);

        const response = await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
        const pageSource = await response?.text() ?? '';
        const headers = response?.headers() ?? {};

        console.log('[AI] Analyzing vulnerabilities with Gemini...');
        const report = await analyzeVulnerabilitiesWithGemini(url, pageSource, headers);

        console.log('[SERVER] Vulnerability scan complete. Sending results.');
        res.json(report);

    } catch (error: any) {
        console.error('[SERVER] Vulnerability scan failed:', error);
        res.status(500).json({ error: error.message || 'An unexpected error occurred during the vulnerability scan.' });
    } finally {
        if (browser) {
            console.log('[PUPPETEER] Closing browser for this request.');
            await browser.close();
        }
    }
});

app.get('/', (req: express.Request, res: express.Response) => {
  res.send('Cookie Care Backend is running!');
});


app.listen(port, () => {
    console.log(`[SERVER] Cookie Care listening on port ${port}`);
});