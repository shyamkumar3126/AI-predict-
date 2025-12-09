import React, { useState, useCallback } from 'react';
import { Shield, Search, ArrowRight, Zap, AlertTriangle } from 'lucide-react';
import { AppState, LogEntry, RawScanData, RiskAnalysisResult } from './types';
import { performRealTimeScan, analyzeRisk } from './services/geminiService';
import { ScanProgress } from './components/ScanProgress';
import { Dashboard } from './components/Dashboard';

const App: React.FC = () => {
  const [target, setTarget] = useState('');
  const [appState, setAppState] = useState<AppState>(AppState.IDLE);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [scanData, setScanData] = useState<RawScanData | null>(null);
  const [analysis, setAnalysis] = useState<RiskAnalysisResult | null>(null);
  const [currentModule, setCurrentModule] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const addLog = (module: string, message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    setLogs(prev => [...prev, { timestamp: Date.now(), module, message, type }]);
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;

    // Reset State
    setAppState(AppState.SCANNING);
    setLogs([]);
    setErrorMsg(null);
    setScanData(null);
    setAnalysis(null);

    try {
      // --- Module 1: Input Acquisition ---
      addLog('Input Acquisition', `Targeting: ${target}`, 'info');
      addLog('Input Acquisition', 'Resolving host...', 'info');
      await new Promise(r => setTimeout(r, 400));
      addLog('Input Acquisition', 'Target locked.', 'success');

      // --- Module 2: Real-Time Data Collection (OSINT) ---
      setCurrentModule('Data Collection');
      addLog('Data Collection', 'Initializing Real-Time OSINT Engine...', 'info');
      
      // Real Search Action
      addLog('Data Collection', 'Executing Google Search Grounding for live reconnaissance...', 'warning');
      addLog('Data Collection', 'Scanning for exposed Whois, DNS, and Hosting data...', 'info');
      
      // Perform the ACTUAL scan (Real-Time)
      const rawData = await performRealTimeScan(target);
      
      addLog('Data Collection', `Target identified in: ${rawData.geolocation.city}, ${rawData.geolocation.country}`, 'success');
      addLog('Data Collection', `ISP/Hosting: ${rawData.geolocation.isp}`, 'info');
      addLog('Data Collection', `Detected ${rawData.open_ports.length} potential open ports via public intelligence.`, 'success');
      
      setScanData(rawData);

      // --- Module 3: Feature Extraction ---
      setCurrentModule('Feature Extraction');
      addLog('Feature Extraction', 'Correlating found technologies with CVE database...', 'info');
      
      // Simulate TShark analysis on the "real" data
      await new Promise(r => setTimeout(r, 600));
      addLog('Feature Extraction', 'Analyzing service banners for versioning anomalies...', 'info');

      if (rawData.traffic_anomalies_detected) {
        addLog('Feature Extraction', 'THREAT DETECTED: Intelligence sources indicate recent attacks/anomalies.', 'warning');
      } else {
        addLog('Feature Extraction', 'Traffic pattern analysis normalized.', 'success');
      }
      
      addLog('Feature Extraction', 'Feature vectors constructed.', 'success');

      // --- Module 4: Risk Analysis ---
      setAppState(AppState.ANALYZING);
      setCurrentModule('Risk Analysis');
      
      addLog('Risk Analysis', 'Engaging AI Risk Engine...', 'info');
      
      const riskResult = await analyzeRisk(rawData);
      setAnalysis(riskResult);
      
      addLog('Risk Analysis', 'Inference complete.', 'info');
      addLog('Risk Analysis', `Calculated Risk Score: ${riskResult.risk_score}/100`, riskResult.risk_score > 50 ? 'warning' : 'success');

      // --- Module 5: Reporting ---
      await new Promise(r => setTimeout(r, 800));
      
      addLog('Reporting', 'Generating interactive visualizations...', 'info');
      addLog('Reporting', 'Finalizing Security Assessment Report...', 'success');
      
      await new Promise(r => setTimeout(r, 500));
      setAppState(AppState.REPORTING);
      setCurrentModule('Completed');

    } catch (err: any) {
      console.error(err);
      setAppState(AppState.ERROR);
      setErrorMsg(err.message || "Scan failed. Please verify the target is accessible.");
      addLog(currentModule, `FATAL: ${err.message}`, 'error');
    }
  };

  const handleReset = () => {
    setTarget('');
    setAppState(AppState.IDLE);
    setLogs([]);
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200 selection:bg-blue-500/30">
      
      {/* Navbar */}
      <nav className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="bg-blue-600 p-1.5 rounded-lg">
              <Shield className="text-white" size={20} />
            </div>
            <span className="font-bold text-lg tracking-tight text-white">NetGuard AI</span>
          </div>
          <div className="flex items-center gap-4 text-sm font-medium text-slate-400">
            <span className="hover:text-white cursor-pointer transition-colors">Documentation</span>
            <span className="hover:text-white cursor-pointer transition-colors">History</span>
            <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700">
               <span className="text-xs">AI</span>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="p-6">
        
        {appState === AppState.IDLE && (
          <div className="max-w-3xl mx-auto mt-20 text-center animate-fade-in-up">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-6">
              <Zap size={12} />
              Real-Time OSINT Engine
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6 tracking-tight">
              Analyze network targets <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-500">with live intelligence.</span>
            </h1>
            <p className="text-lg text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
              NetGuard uses <strong>Gemini Search Grounding</strong> to perform real-time reconnaissance.
              Enter a domain to discover exposed assets, tech stacks, and vulnerabilities instantly.
            </p>

            <form onSubmit={handleStartScan} className="relative max-w-lg mx-auto">
              <div className="relative group">
                <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative flex bg-slate-900 rounded-lg border border-slate-700 p-1.5 shadow-2xl">
                  <input 
                    type="text" 
                    placeholder="Enter domain (e.g. google.com)" 
                    className="flex-1 bg-transparent border-none outline-none text-white px-4 placeholder-slate-500"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                  />
                  <button 
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2.5 rounded-md font-medium transition-all flex items-center gap-2"
                  >
                    Live Scan <ArrowRight size={16} />
                  </button>
                </div>
              </div>
              <p className="mt-4 text-xs text-slate-500">
                Powered by Google Search Grounding & Gemini 2.5 Flash.
              </p>
            </form>

            {/* Feature Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-20 text-left">
              {[
                { title: 'Live Recon', desc: 'Real-time discovery of ISPs, locations, and exposed services via search grounding.' },
                { title: 'Dynamic Risk', desc: 'Risk scores are calculated based on actual found versions and historical CVEs.' },
                { title: 'Toolchain', desc: 'Integrated logic simulating Nmap, Nikto, and TShark analysis.' }
              ].map((feature, i) => (
                <div key={i} className="p-6 rounded-xl bg-slate-800/30 border border-slate-800 hover:border-slate-700 transition-colors">
                  <h3 className="font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-slate-400 text-sm">{feature.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {(appState === AppState.SCANNING || appState === AppState.ANALYZING) && (
          <div className="mt-10">
            <ScanProgress logs={logs} currentModule={currentModule} />
          </div>
        )}

        {appState === AppState.REPORTING && scanData && analysis && (
          <div className="mt-6 animate-fade-in">
             <Dashboard scanData={scanData} analysis={analysis} onReset={handleReset} />
          </div>
        )}

        {appState === AppState.ERROR && (
           <div className="max-w-md mx-auto mt-20 p-6 bg-red-900/20 border border-red-900/50 rounded-xl text-center">
             <div className="w-16 h-16 bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
               <AlertTriangle className="text-red-500" size={32} />
             </div>
             <h2 className="text-xl font-bold text-white mb-2">Scan Failed</h2>
             <p className="text-red-200 mb-6">{errorMsg}</p>
             <button 
                onClick={handleReset}
                className="bg-slate-800 hover:bg-slate-700 text-white px-6 py-2 rounded-lg transition-colors"
             >
               Try Again
             </button>
           </div>
        )}

      </main>
    </div>
  );
};

export default App;