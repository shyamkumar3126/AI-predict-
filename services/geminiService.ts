import { GoogleGenAI, Type } from "@google/genai";
import { RawScanData, RiskAnalysisResult } from "../types";

const getClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found in environment variables.");
  }
  return new GoogleGenAI({ apiKey });
};

// Step 1: Perform Real-Time OSINT (Open Source Intelligence) Reconnaissance
// We use Google Search to get ACTUAL data about the target.
async function performOsintRecon(target: string): Promise<string> {
  const ai = getClient();
  
  // Prompt explicitly asks for technical details available on the open web
  const prompt = `
    Perform a technical reconnaissance on the target: "${target}".
    Find the following real-time information:
    1. Hosting Provider / ISP (e.g., AWS, Cloudflare, Google Cloud).
    2. Geolocation (City, Country).
    3. Domain Registrar (if a domain).
    4. Exposed Technologies (e.g., Nginx, Apache, WordPress, PHP versions).
    5. Any publicly known open ports or services mentioned in technical reports or scanning databases for this target.
    
    If the target is a private IP or invalid, describe generic characteristics of that IP range.
  `;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: {
      tools: [{ googleSearch: {} }], // ENABLE REAL-TIME SEARCH
    }
  });

  return response.text || "No intelligence found.";
}

// Step 2: Parse the OSINT text into Structured JSON
export const performRealTimeScan = async (target: string): Promise<RawScanData> => {
  const ai = getClient();
  
  // 1. Get Real Data
  const osintText = await performOsintRecon(target);
  
  // 2. Convert to JSON
  const systemInstruction = `
    You are a Data Extraction Engine. 
    Convert the provided unstructured network intelligence text into a strict JSON object matching the RawScanData schema.
    
    - Map "Hosting/ISP" to geolocation.isp.
    - Map "Technologies" and "Ports" to open_ports.
    - If specific ports aren't explicitly mentioned, infer common ports based on technologies found (e.g., HTTP -> 80, HTTPS -> 443, MySQL -> 3306).
    - If data is missing, use realistic defaults based on the target type, but prioritize the provided text.
    - "traffic_anomalies_detected" should be true if the text mentions "vulnerabilities", "attacks", or "blacklisted".
  `;

  const prompt = `Extract structured data from this intelligence report about ${target}:\n\n${osintText}`;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: {
      systemInstruction: systemInstruction,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          target: { type: Type.STRING },
          timestamp: { type: Type.STRING },
          dns_records: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                type: { type: Type.STRING },
                value: { type: Type.STRING },
                ttl: { type: Type.INTEGER }
              }
            }
          },
          geolocation: {
            type: Type.OBJECT,
            properties: {
              country: { type: Type.STRING },
              city: { type: Type.STRING },
              isp: { type: Type.STRING }
            }
          },
          open_ports: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                port: { type: Type.INTEGER },
                service: { type: Type.STRING },
                version: { type: Type.STRING },
                state: { type: Type.STRING }
              }
            }
          },
          whois_summary: {
            type: Type.OBJECT,
            properties: {
              registrar: { type: Type.STRING },
              creation_date: { type: Type.STRING },
              expiry_date: { type: Type.STRING }
            }
          },
          traffic_anomalies_detected: { type: Type.BOOLEAN }
        },
        required: ["target", "dns_records", "open_ports", "geolocation", "whois_summary"]
      }
    }
  });

  if (!response.text) {
    throw new Error("Failed to parse scan data");
  }

  return JSON.parse(response.text) as RawScanData;
};

export const analyzeRisk = async (scanData: RawScanData): Promise<RiskAnalysisResult> => {
  const ai = getClient();
  
  // Refined instructions to be more dynamic based on the REAL data we found
  const systemInstruction = `
    You are a Senior Cybersecurity Analyst AI. 
    Analyze the provided NETWORK SCAN DATA. This data is derived from real-time OSINT.
    
    1. Evaluate the risk of the specific ISP/Hosting provider and location.
    2. Check the "version" fields in open_ports. If a version is "unknown", flag it as a configuration warning. If it is old, flag as Critical.
    3. If "traffic_anomalies_detected" is true, drastically increase risk score.
    4. Provide specific CVEs if the technologies found (e.g. Nginx 1.x, Apache 2.x) have known historical vulnerabilities.
    
    Output strictly JSON.
  `;

  const prompt = `Perform Risk Assessment on:\n${JSON.stringify(scanData)}`;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: {
      systemInstruction: systemInstruction,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          risk_score: { type: Type.INTEGER },
          risk_level: { type: Type.STRING, enum: ["Secure", "Low", "Medium", "High", "Critical"] },
          summary: { type: Type.STRING },
          vulnerabilities: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                id: { type: Type.STRING },
                name: { type: Type.STRING },
                severity: { type: Type.STRING, enum: ["Low", "Medium", "High", "Critical"] },
                description: { type: Type.STRING },
                mitigation: { type: Type.STRING },
                cve: { type: Type.STRING }
              }
            }
          },
          recommendations: {
            type: Type.ARRAY,
            items: { type: Type.STRING }
          }
        },
        required: ["risk_score", "risk_level", "summary", "vulnerabilities", "recommendations"]
      }
    }
  });

  if (!response.text) {
    throw new Error("Failed to generate risk analysis");
  }

  return JSON.parse(response.text) as RiskAnalysisResult;
};