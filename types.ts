export interface ScanTarget {
  target: string;
  type: 'domain' | 'ip';
}

export interface DNSRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface OpenPort {
  port: number;
  service: string;
  version?: string;
  state: 'open' | 'filtered' | 'closed';
  reason?: string; // Why is this port open?
  security_risk?: 'None' | 'Low' | 'Medium' | 'High' | 'Critical'; // Risk of this specific port
}

export interface RawScanData {
  target: string;
  timestamp: string;
  dns_records: DNSRecord[];
  geolocation: {
    country: string;
    city: string;
    isp: string;
  };
  open_ports: OpenPort[];
  whois_summary: {
    registrar: string;
    creation_date: string;
    expiry_date: string;
  };
  traffic_anomalies_detected: boolean;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  mitigation: string;
  cve?: string;
}

export interface RiskAnalysisResult {
  security_score: number; // 0-100 (100 is Secure, 0 is Critical)
  risk_level: 'Secure' | 'Moderate' | 'Critical';
  summary: string;
  vulnerabilities: Vulnerability[];
  recommendations: string[];
}

export enum AppState {
  IDLE = 'IDLE',
  SCANNING = 'SCANNING', // Modules 2 & 3
  ANALYZING = 'ANALYZING', // Module 4
  REPORTING = 'REPORTING', // Module 5
  ERROR = 'ERROR'
}

export interface LogEntry {
  timestamp: number;
  module: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error';
}

export interface ScanHistoryItem {
  id: string;
  target: string;
  timestamp: number;
  securityScore: number;
  portCount: number;
}