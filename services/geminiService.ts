import { GoogleGenAI, Type } from "@google/genai";
import { RawScanData, RiskAnalysisResult } from "../types";

const getClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API Key not found in environment variables.");
  }
  return new GoogleGenAI({ apiKey });
};

// Helper: Deterministic Security Calculation
// 100 = Perfect Security (No exposed services)
// < 50 = Critical
const calculateSecurityScore = (scanData: RawScanData): number => {
  let penalty = 0;
  
  // 1. Attack Surface Penalty: 2 points per exposed port
  // Even a standard port increases the attack surface.
  if (scanData.open_ports) {
    penalty += (scanData.open_ports.length * 2);
  }

  // 2. Risk-Based Penalties
  if (scanData.open_ports && scanData.open_ports.length > 0) {
    scanData.open_ports.forEach(port => {
      switch (port.security_risk) {
        case 'Critical': 
          penalty += 40; 
          break; // e.g., Telnet, RDP, Open Database
        case 'High': 
          penalty += 25; 
          break; // e.g., Old Apache, Unencrypted FTP
        case 'Medium': 
          penalty += 15; 
          break; // e.g., Alt HTTP ports (8080), Dev ports
        case 'Low': 
          penalty += 5; 
          break; // e.g., Standard HTTP/HTTPS (Implies web server vulnerability potential)
        case 'None':
          penalty += 2;
          break;
        default: 
          break;
      }

      // 3. Version Disclosure Penalty
      // If a specific version is detected (not "Unknown"), it implies information leakage (+5 penalty)
      if (port.version && port.version.toLowerCase() !== 'unknown') {
        penalty += 5;
      }
    });
  }

  // 4. Anomaly Penalty (WAF detection, error leakage, etc.)
  if (scanData.traffic_anomalies_detected) {
    penalty += 25;
  }

  // Calculate Score (Floor at 0)
  return Math.max(0, 100 - penalty);
};

// Step 1: Perform Real-Time OSINT (Open Source Intelligence) Reconnaissance
async function performOsintRecon(target: string, flags: string = ''): Promise<string> {
  const ai = getClient();
  
  const versionScan = flags.includes('-sV');
  const scriptScan = flags.includes('-sC');

  const prompt = `
    TARGET: "${target}"
    ACTION: Perform a rigorous Network Vulnerability Assessment using Google Search Grounding.
    
    FLAGS: ${versionScan ? '-sV (Version Detection)' : ''} ${scriptScan ? '-sC (Script Scan)' : ''}

    INSTRUCTIONS:
    1.  **Discover Open Ports**: Beyond 80/443, actively look for evidence of management ports (22, 21, 3389), databases (3306, 5432), or alternative web ports (8080, 8443).
    2.  **Fingerprint Services**: Look for specific headers or version numbers associated with this domain in search results (e.g. "Server: Apache/2.4.41").
    3.  **Assess Reputation**: Check for "site:shodan.io ${target}" or vulnerability reports.
    4.  **DIVERSIFY FINDINGS**: Do NOT assume a generic profile. 
        - If the target is a large tech company, look for complex infrastructure but robust security.
        - If the target is a small site or IP, look for misconfigurations.
        - If specific ports are not found, state "Filtered" for them, but assume standard web ports are OPEN.

    REPORT FORMAT:
    - Target: [Target]
    - ISP/Location: [Details]
    - Open Ports: [List with Service, Version, and RISK LEVEL]
    - Anomalies: [Any WAF, Cloudflare, or "Access Denied" patterns]
  `;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: {
      tools: [{ googleSearch: {} }],
    }
  });

  return response.text || "No intelligence found.";
}

// Step 2: Parse the OSINT text into Structured JSON
export const performRealTimeScan = async (target: string, flags: string = ''): Promise<RawScanData> => {
  const ai = getClient();
  const osintText = await performOsintRecon(target, flags);
  
  const systemInstruction = `
    You are a Strict Network Security Parser. 
    Convert the raw intelligence into JSON. 
    
    CRITICAL SCORING RULES FOR 'security_risk':
    - **Critical**: Port 21 (FTP), 23 (Telnet), 3389 (RDP), 445 (SMB), or any Database exposed.
    - **High**: Port 22 (SSH) open to public, or specific OLD versions of Nginx/Apache.
    - **Medium**: Port 8080, 8443, 8000 (Non-standard web), or DNS (53) if likely vulnerable.
    - **Low**: Port 80 (HTTP) and 443 (HTTPS). *Always mark 80 as Low risk due to lack of encryption if found.*
    - **None**: Filtered ports.

    NOTE: If a specific version is found (e.g., "nginx 1.14"), include it. If generic, use "Unknown".
  `;

  const prompt = `Extract structured Nmap-style data from this report about ${target}:\n\n${osintText}`;

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
                state: { type: Type.STRING },
                reason: { type: Type.STRING },
                security_risk: { type: Type.STRING, enum: ['None', 'Low', 'Medium', 'High', 'Critical'] }
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
  
  // 1. Calculate the score programmatically (100 = Secure)
  const calculatedScore = calculateSecurityScore(scanData);
  
  const systemInstruction = `
    You are a Senior Penetration Tester. 
    
    The calculated Security Score for this target is EXACTLY ${calculatedScore} out of 100.
    
    SCORING CONTEXT:
    - 90-100: Excellent (Hardened, minimal surface)
    - 70-89: Good (Standard web ports only)
    - 50-69: Moderate (Some non-standard ports or info leakage)
    - < 50: Critical (Dangerous ports 21/23/3389 or known CVEs)

    TASK:
    1. Set 'security_score' to ${calculatedScore}.
    2. Set 'risk_level' based on the score logic above.
    3. Generate a 'summary' explaining the score. Mention specific ports that lowered the score.
    4. Populate 'vulnerabilities' if the score is < 80 or if specific versions allow for CVE mapping.
  `;

  const prompt = `Perform Vulnerability Assessment on:\n${JSON.stringify(scanData)}`;

  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
    config: {
      systemInstruction: systemInstruction,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          security_score: { type: Type.INTEGER },
          risk_level: { type: Type.STRING, enum: ["Secure", "Moderate", "Critical"] },
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
        required: ["security_score", "risk_level", "summary", "vulnerabilities", "recommendations"]
      }
    }
  });

  if (!response.text) {
    throw new Error("Failed to generate risk analysis");
  }

  const result = JSON.parse(response.text) as RiskAnalysisResult;
  
  // Double-check: Force the score to match our calculation
  result.security_score = calculatedScore;
  
  return result;
};