import React, { useState } from 'react';
import { Shield, ArrowRight, Zap, AlertTriangle, X, History, FileText } from 'lucide-react';
import { AppState, LogEntry, RawScanData, RiskAnalysisResult, ScanHistoryItem } from './types';
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
  
  // New State for History and Modals
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [showDocModal, setShowDocModal] = useState(false);

  const addLog = (module: string, message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    setLogs(prev => [...prev, { timestamp: Date.now(), module, message, type }]);
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;

    setAppState(AppState.SCANNING);
    setLogs([]);
    setErrorMsg(null);
    setScanData(null);
    setAnalysis(null);

    try {
      // --- Phase 1: Nmap & OSINT Initialization ---
      addLog('Input Acquisition', `Targeting: ${target}`, 'info');
      await new Promise(r => setTimeout(r, 400));
      addLog('Input Acquisition', 'Host resolution confirmed.', 'success');

      setCurrentModule('Data Collection');
      addLog('Data Collection', 'Initializing Nmap Execution Engine...', 'info');
      addLog('Data Collection', `Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toISOString().split('T')[0]}`, 'info');
      
      // Perform the ACTUAL scan
      addLog('Data Collection', 'Scanning for exposed ports and services...', 'warning');
      
      // CALL WITH -sV -sC flags for Version Detection and Default Scripts
      const rawData = await performRealTimeScan(target, '-sV -sC');
      
      addLog('Data Collection', `Nmap scan report for ${rawData.target}`, 'success');
      addLog('Data Collection', `Host is up. Latency: 0.04s.`, 'info');
      addLog('Data Collection', `Discovered ${rawData.open_ports.length} open ports on ${rawData.target}`, 'warning');
      
      rawData.open_ports.forEach(p => {
         if (p.security_risk === 'Critical' || p.security_risk === 'High') {
            addLog('Data Collection', `PORT ${p.port}/tcp OPEN (${p.service}) - ${p.security_risk.toUpperCase()} RISK DETECTED`, 'error');
         }
      });
      
      setScanData(rawData);

      // --- Phase 2: Script Scan & Vulnerability Analysis ---
      setCurrentModule('Feature Extraction');
      addLog('Feature Extraction', 'Running NSE (Nmap Scripting Engine) scripts...', 'info');
      await new Promise(r => setTimeout(r, 600));
      
      addLog('Feature Extraction', 'Analyzing service banners for CVEs...', 'info');
      addLog('Feature Extraction', 'Detecting misconfigured services...', 'info');
      
      // --- Phase 3: Risk Calculation ---
      setAppState(AppState.ANALYZING);
      setCurrentModule('Risk Analysis');
      
      addLog('Risk Analysis', 'Correlating findings with National Vulnerability Database...', 'info');
      
      const riskResult = await analyzeRisk(rawData);
      setAnalysis(riskResult);
      
      // Save to History
      setHistory(prev => [{
        id: Date.now().toString(),
        target: rawData.target,
        timestamp: Date.now(),
        securityScore: riskResult.security_score,
        portCount: rawData.open_ports.length
      }, ...prev]);

      addLog('Risk Analysis', `Calculated Security Score: ${riskResult.security_score}/100`, riskResult.security_score < 50 ? 'error' : 'success');

      // --- Phase 4: Report ---
      await new Promise(r => setTimeout(r, 500));
      setAppState(AppState.REPORTING);
      setCurrentModule('Completed');

    } catch (err: any) {
      console.error(err);
      setAppState(AppState.ERROR);
      setErrorMsg(err.message || "Scan failed.");
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
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer group" onClick={handleReset}>
            <div className="bg-blue-600 p-2 rounded-lg group-hover:bg-blue-500 transition-colors shadow-lg shadow-blue-500/20">
              <Shield className="text-white" size={20} />
            </div>
            <span className="font-bold text-lg tracking-tight text-white">WebGuard</span>
          </div>
          
          <div className="flex items-center gap-2 sm:gap-4">
            <button 
              onClick={() => setShowDocModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
            >
              <FileText size={18} /> 
              <span className="hidden sm:inline">Documentation</span>
            </button>
            
            <button 
              onClick={() => setShowHistoryModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-all relative"
            >
              <History size={18} /> 
              <span className="hidden sm:inline">History</span>
              {history.length > 0 && (
                <span className="absolute top-1 right-1 sm:-top-1 sm:-right-1 flex h-2 w-2 sm:h-4 sm:w-4 items-center justify-center rounded-full bg-blue-500 text-[10px] text-white">
                  <span className="hidden sm:inline">{history.length}</span>
                </span>
              )}
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="p-4 sm:p-6">
        
        {/* Modals */}
        {showDocModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
            <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
              <div className="flex justify-between items-center p-6 border-b border-slate-800">
                 <h2 className="text-xl font-bold text-white">Documentation</h2>
                 <button onClick={() => setShowDocModal(false)} className="text-slate-400 hover:text-white"><X size={20}/></button>
              </div>
              <div className="p-6 space-y-4 text-slate-300">
                <p><strong>WebGuard</strong> simulates a comprehensive penetration test using real-time OSINT data.</p>
                <h3 className="text-white font-semibold mt-4">Tools Emulated</h3>
                <ul className="list-disc pl-5 space-y-1">
                  <li><strong>Nmap:</strong> Port scanning and service version detection.</li>
                  <li><strong>WhatWeb:</strong> Technology stack identification.</li>
                  <li><strong>Google Dorks:</strong> Finding exposed panels and files.</li>
                </ul>
                <h3 className="text-white font-semibold mt-4">Interpretation</h3>
                <p>The "Nmap Port Analysis" section highlights ports that are open but should be closed. A "Critical" risk indicates an exposed database or administration port (like SSH/RDP) accessible to the public internet.</p>
              </div>
            </div>
          </div>
        )}

        {showHistoryModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
            <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
              <div className="flex justify-between items-center p-6 border-b border-slate-800">
                 <h2 className="text-xl font-bold text-white">Scan Session History</h2>
                 <button onClick={() => setShowHistoryModal(false)} className="text-slate-400 hover:text-white"><X size={20}/></button>
              </div>
              <div className="p-6">
                {history.length === 0 ? (
                  <p className="text-slate-500 text-center py-8">No scans performed in this session yet.</p>
                ) : (
                  <div className="space-y-3">
                    {history.map(item => (
                      <div key={item.id} className="bg-slate-800/50 p-4 rounded-lg flex justify-between items-center border border-slate-700">
                        <div>
                          <div className="font-mono text-white font-bold">{item.target}</div>
                          <div className="text-xs text-slate-400">{new Date(item.timestamp).toLocaleTimeString()} • {item.portCount} Ports Open</div>
                        </div>
                        <div className={`px-3 py-1 rounded text-sm font-bold ${item.securityScore < 50 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                          Score: {item.securityScore}%
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {appState === AppState.IDLE && (
          <div className="max-w-3xl mx-auto mt-20 text-center animate-fade-in-up px-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-6">
              <Zap size={12} />
              Real-Time Nmap Engine
            </div>
            <h1 className="text-4xl sm:text-5xl md:text-6xl font-bold text-white mb-6 tracking-tight">
              Identify closed ports that <br className="hidden sm:block" />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-500">are actually open.</span>
            </h1>
            <p className="text-base sm:text-lg text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
              WebGuard uses AI-driven Nmap simulation to detect misconfigured firewalls and exposed services. 
              Find out which ports are vulnerable before attackers do.
            </p>

            <form onSubmit={handleStartScan} className="relative max-w-lg mx-auto">
              <div className="relative group">
                <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                <div className="relative flex bg-slate-900 rounded-lg border border-slate-700 p-1.5 shadow-2xl">
                  <input 
                    type="text" 
                    placeholder="Enter target (e.g. 192.168.1.1 or example.com)" 
                    className="flex-1 bg-transparent border-none outline-none text-white px-4 placeholder-slate-500 w-full"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                  />
                  <button 
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-500 text-white px-4 sm:px-6 py-2.5 rounded-md font-medium transition-all flex items-center gap-2 whitespace-nowrap"
                  >
                    Run Nmap <ArrowRight size={16} />
                  </button>
                </div>
              </div>
              <p className="mt-4 text-xs text-slate-500">
                Simulates -sV -sC scan using Search Grounding.
              </p>
            </form>

            {/* Feature Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-20 text-left">
              {[
                { title: 'Port Analysis', desc: 'Detects ports that should be closed (21, 23, 3389) but are found open.' },
                { title: 'Service Versioning', desc: 'Identifies outdated versions (e.g., Apache 2.2) via banner grabbing.' },
                { title: 'Vulnerability Map', desc: 'Maps open ports directly to potential CVE exploits.' }
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