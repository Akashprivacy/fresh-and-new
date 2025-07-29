
import express, { Request, Response } from 'express';
import puppeteer, { type Cookie, type Page, type Frame, Browser } from 'puppeteer';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { CookieCategory, type CookieInfo, type ScanResultData, type TrackerInfo, type DpaAnalysisResult, type DpaPerspective, type VulnerabilityReport, type GeminiScanAnalysis } from './types.js';

dotenv.config();

const app = express();
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
  'http://127.0.0.1:5500'
].filter(Boolean); // Removes any falsy values (like an unset process.env.FRONTEND_URL)

console.log(`[CORS] Allowed Origins configured: ${allowedOrigins.join(', ')}`);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, or server-to-server)
    if (!origin) {
      console.log('[CORS] Allowing request with no origin.');
      return callback(null, true);
    }
    
    // Check if the incoming origin is on our list of allowed sites.
    if (allowedOrigins.includes(origin)) {
      console.log(`[CORS] Origin allowed: ${origin}`);
      return callback(null, true);
    }

    // If the origin is not on our list, block the request.
    const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
    console.error(`[CORS] Blocking request. ${msg}`);
    return callback(new Error(msg), false);
  },
};

// This is CRITICAL. It tells the server to handle the browser's preflight OPTIONS request
// before it attempts the actual POST/GET/etc. request. This must come before other routes.
app.options('*', cors(corsOptions)); 

// Use the CORS middleware for all other requests.
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
    'google-analytics.com', 'googletagmanager.com', 'analytics.google.com', 'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'connect.facebook.net', 'facebook.com/tr', 'c.clarity.ms', 'clarity.ms', 'hotjar.com', 'hotjar.io', 'hjid.hotjar.com', 'hubspot.com', 'hs-analytics.net', 'track.hubspot.com', 'linkedin.com/px', 'ads.linkedin.com', 'twitter.com/i/ads', 'ads-twitter.com', 'bing.com/ads', 'semrush.com', 'optimizely.com', 'vwo.com', 'crazyegg.com', 'taboola.com', 'outbrain.com', 'criteo.com', 'addthis.com', 'sharethis.com', 'tiqcdn.com', // Tealium
];

const getHumanReadableExpiry = (puppeteerCookie: Cookie): string => {
    if (puppeteerCookie.session || puppeteerCookie.expires === -1) return "Session";
    const expiryDate = new Date(puppeteerCookie.expires * 1000);
    const now = new Date();
    const diffSeconds = (expiryDate.getTime() - now.getTime()) / 1000;
    if (diffSeconds < 0) return "Expired";
    if (diffSeconds < 3600) return `${Math.round(diffSeconds / 60)} minutes`;
    if (diffSeconds < 86400) return `${Math.round(diffSeconds / 3600)} hours`;
    if (diffSeconds < 86400 * 30) return `${Math.round(diffSeconds / 86400)} days`;
    if (diffSeconds < 86400 * 365) return `${Math.round(diffSeconds / (86400 * 30))} months`;
    const years = parseFloat((diffSeconds / (86400 * 365)).toFixed(1));
    return `${years} year${years > 1 ? 's' : ''}`;
};

async function findAndClickButton(frame: Frame, keywords: string[]): Promise<boolean> {
  for (const text of keywords) {
    try {
      const clicked = await frame.evaluate((t) => {
        const selectors = 'button, a, [role="button"], input[type="submit"], input[type="button"]';
        const elements = Array.from(document.querySelectorAll(selectors));
        const target = elements.find(el => {
            const elText = (el.textContent || el.getAttribute('aria-label') || (el as HTMLInputElement).value || '').trim().toLowerCase();
            return elText.includes(t)
        });
        if (target) {
          (target as HTMLElement).click();
          return true;
        }
        return false;
      }, text);
      if (clicked) {
        console.log(`[CONSENT] Clicked button containing: "${text}"`);
        await new Promise(r => setTimeout(r, 1500)); // Wait for actions post-click
        return true;
      }
    } catch (error) {
       if (error instanceof Error && !frame.isDetached()) {
         console.warn(`[CONSENT] Warning on frame ${frame.url()}: ${error.message}`);
       }
    }
  }
  return false;
}

async function handleConsent(page: Page, action: 'accept' | 'reject'): Promise<boolean> {
  console.log(`[CONSENT] Attempting to ${action} consent...`);
  const acceptKeywords = ["accept all", "allow all", "agree to all", "accept cookies", "agree", "accept", "allow", "i agree", "ok", "got it", "continue", "i understand"];
  const rejectKeywords = ["reject all", "deny all", "decline all", "reject cookies", "disagree", "reject", "deny", "decline", "necessary only", "strictly necessary"];
  
  const keywords = action === 'accept' ? acceptKeywords : rejectKeywords;

  if (await findAndClickButton(page.mainFrame(), keywords)) return true;
  for (const frame of page.frames()) {
    if (!frame.isDetached() && frame !== page.mainFrame() && await findAndClickButton(frame, keywords)) return true;
  }
  
  console.log(`[CONSENT] No actionable button found for "${action}".`);
  return false;
}

const collectPageData = async (page: Page): Promise<{ cookies: Cookie[], trackers: Set<string> }> => {
    const trackers = new Set<string>();
    const requestListener = (request: any) => {
        const reqUrl = request.url();
        const trackerDomain = knownTrackerDomains.find(domain => reqUrl.includes(domain));
        if (trackerDomain) trackers.add(`${trackerDomain}|${reqUrl}`);
    };
    page.on('request', requestListener);
    
    await page.reload({ waitUntil: 'networkidle2' });
    
    const cookies = await page.cookies();
    
    page.off('request', requestListener); // Clean up listener
    return { cookies, trackers };
}

interface ApiScanRequestBody { url: string; }

app.post('/api/scan', async (req: Request<{}, any, ApiScanRequestBody>, res: Response<ScanResultData | { error: string }>) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  console.log(`[SERVER] Received scan request for: ${url}`);
  let browser: Browser | null = null;
  try {
    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--start-maximized'] });
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
    await page.setViewport({ width: 1920, height: 1080 });

    // --- State 1: Pre-Consent ---
    console.log('[SCAN] Capturing pre-consent state...');
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 180000 }); // Increased timeout to 3 minutes
    const screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });
    const { cookies: preConsentCookies, trackers: preConsentTrackers } = await collectPageData(page);
    console.log(`[SCAN] Pre-consent: ${preConsentCookies.length} cookies, ${preConsentTrackers.size} trackers.`);
    
    // --- State 2: Post-Rejection ---
    console.log('[SCAN] Capturing post-rejection state...');
    await handleConsent(page, 'reject');
    const { cookies: postRejectCookies, trackers: postRejectTrackers } = await collectPageData(page);
    console.log(`[SCAN] Post-rejection: ${postRejectCookies.length} cookies, ${postRejectTrackers.size} trackers.`);
    
    // --- State 3: Post-Acceptance ---
    console.log('[SCAN] Capturing post-acceptance state...');
    await page.reload({ waitUntil: 'networkidle2' }); // Reload to reset state before accepting
    await handleConsent(page, 'accept');
    const { cookies: postAcceptCookies, trackers: postAcceptTrackers } = await collectPageData(page);
    console.log(`[SCAN] Post-acceptance: ${postAcceptCookies.length} cookies, ${postAcceptTrackers.size} trackers.`);

    const allCookieMap = new Map<string, any>();
    const allTrackerMap = new Map<string, any>();

    const processItems = (map: Map<string, any>, items: any[], state: string, isCookie: boolean) => {
      items.forEach((item: any) => {
        const key = isCookie ? `${item.name}|${item.domain}|${item.path}` : `${item.split('|')[0]}|${item.split('|')[1]}`;
        if (!map.has(key)) map.set(key, { states: new Set() });
        map.get(key).states.add(state);
        map.get(key).data = item;
      });
    };
    
    processItems(allCookieMap, preConsentCookies, 'pre-consent', true);
    processItems(allCookieMap, postRejectCookies, 'post-rejection', true);
    processItems(allCookieMap, postAcceptCookies, 'post-acceptance', true);
    processItems(allTrackerMap, Array.from(preConsentTrackers), 'pre-consent', false);
    processItems(allTrackerMap, Array.from(postRejectTrackers), 'post-rejection', false);
    processItems(allTrackerMap, Array.from(postAcceptTrackers), 'post-acceptance', false);

    const itemsForAnalysis = {
      cookies: Array.from(allCookieMap.entries()).map(([key, value]) => ({
        key, name: value.data.name, provider: value.data.domain, states: Array.from(value.states)
      })),
      trackers: Array.from(allTrackerMap.entries()).map(([key, value]) => ({
        key, provider: value.data.split('|')[0], states: Array.from(value.states)
      })),
    };
    
    if (itemsForAnalysis.cookies.length === 0 && itemsForAnalysis.trackers.length === 0) {
      return res.json({
          cookies: [], trackers: [], screenshotBase64,
          compliance: {
              gdpr: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
              ccpa: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
          }
      });
    }

    const cookiePrompt = `
      You are a world-class privacy and web compliance expert AI.
      Your task is to analyze cookie and tracker data from "${url}" and return your findings as a single, valid JSON object.

      **ULTRA-CRITICAL INSTRUCTIONS (FAILURE TO COMPLY WILL RENDER YOUR OUTPUT USELESS):**
      1.  Your ENTIRE response MUST be a single, raw, valid JSON object.
      2.  START your response immediately with "{" and END it with "}".
      3.  DO NOT include \`\`\`json, \`\`\`, explanations, or any text outside of the JSON object.
      4.  JSON STRING ESCAPING IS PARAMOUNT: You MUST correctly escape all special characters like double quotes (") and newlines (\\n) within all string values to ensure the final output is machine-parseable.
      
      Data for Analysis:
      ${JSON.stringify(itemsForAnalysis, null, 2)}
      
      Analyze the data and return a JSON object that adheres strictly to the provided schema.
      1.  **"cookies" & "trackers"**: For each item:
          - **key**: The original unique key (unmodified).
          - **category**: Categorize with extreme accuracy: 'Necessary', 'Functional', 'Analytics', 'Marketing', or 'Unknown'. Only essential-for-operation items are 'Necessary'.
          - **purpose**: (For cookies only) A CONCISE, one-sentence description of its function.
          - **complianceStatus**: Determine based on its 'states' and 'category':
              - 'Compliant' if category is 'Necessary'.
              - 'Pre-Consent Violation' if state includes 'pre-consent' AND category is NOT 'Necessary'.
              - 'Post-Rejection Violation' if state includes 'post-rejection' AND category is NOT 'Necessary'.
              - 'Compliant' for all other cases.
      2.  **"compliance"**: An object with "gdpr" and "ccpa" keys. For both, provide:
          - **riskLevel**: 'Low', 'Medium', or 'High'. Any violation makes the risk 'High'. Many non-necessary but compliant trackers suggest 'Medium' risk.
          - **assessment**: A brief, expert summary explaining the risk level. Start with the number of violations found (e.g., "High risk due to 5 pre-consent violations.").
    `;

    const cookieResponseSchema = {
        type: Type.OBJECT,
        properties: {
          cookies: { type: Type.ARRAY, items: {
            type: Type.OBJECT, properties: { key: { type: Type.STRING }, category: { type: Type.STRING }, purpose: { type: Type.STRING }, complianceStatus: { type: Type.STRING } }, required: ["key", "category", "purpose", "complianceStatus"],
          }},
          trackers: { type: Type.ARRAY, items: {
            type: Type.OBJECT, properties: { key: { type: Type.STRING }, category: { type: Type.STRING }, complianceStatus: { type: Type.STRING } }, required: ["key", "category", "complianceStatus"],
          }},
          compliance: { type: Type.OBJECT, properties: {
              gdpr: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
              ccpa: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
          }, required: ['gdpr', 'ccpa']},
        },
        required: ["cookies", "trackers", "compliance"],
    };
    
    const geminiResult = await withRetry(() => ai.models.generateContent({
        model,
        contents: cookiePrompt,
        config: {
            responseMimeType: "application/json",
            responseSchema: cookieResponseSchema,
        },
    }));
    
    const geminiText = geminiResult.text;
    if (!geminiText) throw new Error('Gemini API returned an empty response.');

    const jsonString = extractJson(geminiText);
    let analysis: GeminiScanAnalysis;
    try {
      analysis = JSON.parse(jsonString) as GeminiScanAnalysis;
    } catch(parseError: any) {
      console.error("[FATAL] Failed to parse JSON from Gemini for cookie scan.");
      console.error("----- RAW GEMINI TEXT -----");
      console.error(geminiText);
      console.error("----- EXTRACTED JSON STRING -----");
      console.error(jsonString);
      console.error("----- PARSE ERROR -----");
      console.error(parseError);
      throw new Error(`AI analysis returned a malformed response. Parsing error: ${parseError.message}`);
    }

    const cookieAnalysisMap = new Map(analysis.cookies.map((c) => [c.key, c]));
    const trackerAnalysisMap = new Map(analysis.trackers.map((t) => [t.key, t]));
    const scannedUrlHostname = new URL(url).hostname;

    const finalEnrichedCookies: CookieInfo[] = Array.from(allCookieMap.values()).map(c => {
        const key = `${c.data.name}|${c.data.domain}|${c.data.path}`;
        const analyzed = cookieAnalysisMap.get(key);
        const domain = c.data.domain.startsWith('.') ? c.data.domain : `.${c.data.domain}`;
        const rootDomain = `.${scannedUrlHostname.replace(/^www\./, '')}`;
        return {
            key, name: c.data.name, provider: c.data.domain, expiry: getHumanReadableExpiry(c.data),
            party: domain.endsWith(rootDomain) ? 'First' : 'Third',
            isHttpOnly: c.data.httpOnly, isSecure: c.data.secure,
            complianceStatus: analyzed?.complianceStatus || 'Unknown',
            category: analyzed?.category || CookieCategory.UNKNOWN,
            purpose: analyzed?.purpose || 'No purpose determined.',
        };
    });

    const finalEnrichedTrackers: TrackerInfo[] = Array.from(allTrackerMap.values()).map(t => {
        const [provider, trackerUrl] = t.data.split('|');
        const key = `${provider}|${trackerUrl}`;
        const analyzed = trackerAnalysisMap.get(key);
        return {
            key, url: trackerUrl, provider,
            category: analyzed?.category || CookieCategory.UNKNOWN,
            complianceStatus: analyzed?.complianceStatus || 'Unknown',
        };
    });

    res.json({ cookies: finalEnrichedCookies, trackers: finalEnrichedTrackers, compliance: analysis.compliance, screenshotBase64 });

  } catch (error) {
    const message = error instanceof Error ? error.message : "An unknown error occurred.";
    console.error('[SERVER] Scan failed:', message);
    res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
  } finally {
    if (browser) await browser.close();
  }
});


interface DpaReviewRequestBody { dpaText: string; perspective: DpaPerspective; }

app.post('/api/review-dpa', async (req: Request<{}, any, DpaReviewRequestBody>, res: Response<DpaAnalysisResult | { error: string }>) => {
    const { dpaText, perspective } = req.body;
    if (!dpaText || !perspective) {
        return res.status(400).json({ error: 'DPA text and perspective are required' });
    }

    console.log(`[SERVER] Received DPA review request from perspective: ${perspective}`);

    try {
        const perspectiveText = perspective === 'controller' ? 'Data Controller' : 'Data Processor';
        const dpaPrompt = `
          You are a world-class data privacy lawyer AI.
          Your task is to review a Data Processing Agreement (DPA) and return your analysis as a single, valid JSON object.

          **ULTRA-CRITICAL INSTRUCTIONS (FAILURE TO COMPLY WILL RENDER YOUR OUTPUT USELESS):**
          1.  Your ENTIRE response MUST be a single, raw, valid JSON object.
          2.  START your response immediately with "{" and END it with "}".
          3.  DO NOT include \`\`\`json, \`\`\`, explanations, or any text outside of the JSON object.
          4.  JSON STRING ESCAPING IS PARAMOUNT: You MUST correctly escape all special characters like double quotes (") and newlines (\\n) within all string values ("summary", "risk", "recommendation", etc.) to ensure the final output is machine-parseable.

          Analyze major clauses (e.g., Subject Matter, Data Subject Rights, Processor's Obligations, Sub-processing, Data Transfers, Liability, Audits, Breach Notification, Termination) from the powerful perspective of a **${perspectiveText}**.
          For each clause:
          1.  **summary**: A neutral summary of what the clause contains.
          2.  **risk**: A detailed analysis of the risks for the specified perspective. Be specific.
          3.  **riskLevel**: 'Low', 'Medium', 'High'. If a key clause is missing or vague, assign 'High' risk.
          4.  **recommendation**: A concrete, actionable recommendation for negotiation or clarification.
          5.  **negotiationTip**: A sharp, strategic tip for negotiation. Example: "Propose capping liability at 12 months of fees paid." or "Demand a specific timeframe for breach notification (e.g., 24 hours)."

          Also provide an **overallRisk** object with a 'level' and 'summary'.

          DPA Text to Analyze:
          ---
          ${dpaText}
          ---
        `;

        const dpaResponseSchema = {
            type: Type.OBJECT,
            properties: {
                overallRisk: { type: Type.OBJECT, properties: {
                    level: { type: Type.STRING, description: "Overall risk level, can be 'Low', 'Medium', or 'High'." },
                    summary: { type: Type.STRING, description: "A brief summary explaining the overall risk level based on the analysis."}
                }, required: ["level", "summary"]},
                analysis: { type: Type.ARRAY, items: {
                    type: Type.OBJECT, properties: {
                        clause: { type: Type.STRING, description: "The name of the DPA clause being analyzed." },
                        summary: { type: Type.STRING, description: "A neutral summary of what the clause contains." },
                        risk: { type: Type.STRING, description: "A detailed analysis of the risks for the specified perspective." },
                        riskLevel: { type: Type.STRING, description: "Risk level for this clause: 'Low', 'Medium', 'High'." },
                        recommendation: { type: Type.STRING, description: "A concrete, actionable recommendation for negotiation or clarification." },
                        negotiationTip: { type: Type.STRING, description: "A sharp, strategic tip for negotiation." }
                    }, required: ["clause", "summary", "risk", "riskLevel", "recommendation", "negotiationTip"]
                }}
            },
            required: ["overallRisk", "analysis"]
        };

        const result = await withRetry(() => ai.models.generateContent({
            model,
            contents: dpaPrompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: dpaResponseSchema,
            },
        }));

        const resultText = result.text;
        if (!resultText) {
            throw new Error('Gemini API returned an empty response for DPA analysis.');
        }
        
        const jsonString = extractJson(resultText);
        const analysisResult = JSON.parse(jsonString) as DpaAnalysisResult;
        res.json(analysisResult);

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] DPA review failed:', message);
        res.status(500).json({ error: `Failed to review DPA. ${message}` });
    }
});


interface VulnerabilityScanBody { url: string; }

app.post('/api/scan-vulnerability', async (req: Request<{}, any, VulnerabilityScanBody>, res: Response<VulnerabilityReport | { error: string }>) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`[SERVER] Received vulnerability scan request for: ${url}`);
    let browser: Browser | null = null;
    try {
        browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
        const page = await browser.newPage();
        
        const response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 120000 });
        const headers = response?.headers() || {};
        const html = await page.content();
        const externalScripts = await page.$$eval('script[src]', scripts => (scripts.map(s => s.getAttribute('src')).filter(Boolean) as string[]));
        const hasPasswordFields = (await page.$$('input[type="password"]')).length > 0;
        
        const vulnerabilityPrompt = `
            You are a world-class penetration tester and cybersecurity analyst AI.
            Your task is to perform a passive security assessment of ${url} and return your findings as a single, valid JSON object.

            **ULTRA-CRITICAL INSTRUCTIONS (FAILURE TO COMPLY WILL RENDER YOUR OUTPUT USELESS):**
            1.  Your ENTIRE response MUST be a single, raw, valid JSON object.
            2.  START your response immediately with "{" and END it with "}".
            3.  DO NOT include \`\`\`json, \`\`\`, explanations, or any text outside of the JSON object.
            4.  **JSON STRING ESCAPING IS PARAMOUNT:** Within the "remediation" field, which may contain code examples, you MUST correctly escape all special characters. Backslashes (\\), double quotes ("), and newlines (\\n) MUST be properly escaped (as \\\\, \\", and \\n respectively). This is the most important rule to prevent parsing errors.

            **Provided Data for Analysis:**
            1.  Response Headers: ${JSON.stringify(headers, null, 2)}
            2.  External Scripts: ${JSON.stringify(externalScripts, null, 2)}
            3.  Has Password Fields: ${hasPasswordFields}
            4.  HTML (first 8000 chars): ${html.substring(0, 8000)}

            **Analysis Instructions (Be Extremely Thorough):**
            1.  **Security Headers**: Meticulously check for missing or weak security headers (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy). For CSP, analyze its strength. Is it too permissive?
            2.  **Information Disclosure**: Identify any revealing headers like 'Server', 'X-Powered-By', 'X-AspNet-Version'.
            3.  **Cookie Security**: From the 'set-cookie' headers (if any), analyze if cookies are missing 'HttpOnly', 'Secure', or 'SameSite=Strict/Lax' attributes.
            4.  **Supply-Chain Risk**: For each external script, assess the potential risk. Is it a well-known, reputable provider (e.g., Google, Cloudflare) or an obscure one? Mention any known risks with common third-party scripts.
            5.  **HTML Analysis**: Check for insecure form actions (HTTP links), autocomplete enabled on sensitive fields, or any exposed API keys or comments that could be a security risk.
        `;
        
        const vulnerabilityResponseSchema = {
            type: Type.OBJECT,
            properties: {
                overallScore: { type: Type.NUMBER, description: "A security score from 0 (worst) to 100 (best), based on the severity and number of findings." },
                riskLevel: { type: Type.STRING, description: "Overall risk level: 'Critical', 'High', 'Medium', 'Low', or 'Informational'." },
                summary: { type: Type.STRING, description: "A high-level, expert summary of the website's security posture." },
                vulnerabilities: {
                    type: Type.ARRAY,
                    items: {
                        type: Type.OBJECT,
                        properties: {
                            title: { type: Type.STRING, description: "A clear, impactful title for the vulnerability." },
                            description: { type: Type.STRING, description: "A detailed explanation of the vulnerability and its potential impact, as an expert would describe it." },
                            risk: { type: Type.STRING, description: "Risk level for this finding: 'Critical', 'High', 'Medium', 'Low', 'Informational'." },
                            remediation: { type: Type.STRING, description: "A concrete, actionable plan with code examples to fix the vulnerability." },
                            owaspCategory: { type: Type.STRING, description: "The most relevant OWASP Top 10 2011 category (e.g., 'A05:2021-Security Misconfiguration')." }
                        },
                        required: ["title", "description", "risk", "remediation", "owaspCategory"]
                    }
                }
            },
            required: ["overallScore", "riskLevel", "summary", "vulnerabilities"]
        };
        
        const result = await withRetry(() => ai.models.generateContent({
            model,
            contents: vulnerabilityPrompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: vulnerabilityResponseSchema,
            },
        }));
        
        const resultText = result.text;
        if (!resultText) {
            throw new Error('Gemini API returned an empty response for vulnerability scan.');
        }

        const jsonString = extractJson(resultText);
        let report: VulnerabilityReport;
        try {
            report = JSON.parse(jsonString) as VulnerabilityReport;
        } catch (parseError: any) {
            console.error("Failed to parse JSON from Gemini for vulnerability scan.");
            console.error("Original Text:", resultText);
            console.error("Extracted Text:", jsonString);
            throw new Error(`AI analysis returned a malformed response. Parsing error: ${parseError.message}`);
        }
        res.json(report);

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred during the vulnerability scan.";
        console.error('[SERVER] Vulnerability scan failed:', message);
        res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
    } finally {
        if (browser) await browser.close();
    }
});


app.listen(port, () => {
  console.log(`[SERVER] Cookie Care listening on port ${port}`);
});
