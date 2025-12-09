import React from 'react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend 
} from 'recharts';
import { AlertTriangle, CheckCircle, ShieldAlert, Globe, Server, Activity, FileText, Database, Terminal, Settings } from 'lucide-react';
import { RawScanData, RiskAnalysisResult } from '../types';

interface DashboardProps {
  scanData: RawScanData;
  analysis: RiskAnalysisResult;
  onReset: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ scanData, analysis, onReset }) => {
  // Data for Risk Score Gauge (simulated with Pie)
  const riskData = [
    { name: 'Risk', value: analysis.risk_score },
    { name: 'Safe', value: 100 - analysis.risk_score }
  ];
  
  const getRiskColor = (score: number) => {
    if (score < 30) return '#22c55e';
    if (score < 60) return '#eab308';
    if (score < 80) return '#f97316';
    return '#ef4444';
  };

  const riskColor = getRiskColor(analysis.risk_score);

  // Data for Port Distribution
  const portStats = scanData.open_ports.reduce((acc, curr) => {
    acc[curr.service] = (acc[curr.service] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const portChartData = Object.entries(portStats).map(([name, value]) => ({ name, value }));

  const tools = [
    { name: 'Nmap', type: 'Network Discovery' },
    { name: 'Nikto', type: 'Web Scanner' },
    { name: 'OpenVAS', type: 'Vulnerability Analysis' },
    { name: 'TShark', type: 'Packet Analysis' },
    { name: 'WhatWeb', type: 'Tech Stack ID' },
    { name: 'Shodan', type: 'Intelligence' },
    { name: 'SQLite', type: 'Data Storage' },
    { name: 'ReportLab', type: 'Reporting' },
    { name: 'Plotly', type: 'Visualization' },
  ];

  return (
    <div className="w-full max-w-7xl mx-auto space-y-6 pb-20">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Assessment Report</h1>
          <div className="flex items-center gap-2 text-slate-400">
            <Globe size={16} />
            <span className="font-mono">{scanData.target}</span>
            <span className="mx-2">•</span>
            <span>{new Date().toLocaleDateString()}</span>
          </div>
        </div>
        <button 
          onClick={onReset}
          className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
        >
          New Scan
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        
        {/* Risk Score Card */}
        <div className="md:col-span-4 bg-slate-800 rounded-xl p-6 border border-slate-700 relative overflow-hidden">
          <h2 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <ShieldAlert className="text-blue-400" /> Overall Risk Score
          </h2>
          <div className="h-48 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  startAngle={180}
                  endAngle={0}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  <Cell key="risk" fill={riskColor} />
                  <Cell key="safe" fill="#334155" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 translate-y-2 text-center">
              <span className="text-5xl font-bold text-white block">{analysis.risk_score}</span>
              <span className="text-sm font-medium" style={{ color: riskColor }}>{analysis.risk_level.toUpperCase()}</span>
            </div>
          </div>
          <p className="text-slate-400 text-sm mt-2 text-center">
            {analysis.summary}
          </p>
        </div>

        {/* Target Info */}
        <div className="md:col-span-4 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Server className="text-blue-400" /> Target Reconnaissance
          </h2>
          <div className="space-y-4 text-sm">
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">IP / Host</span>
              <span className="text-slate-200 font-mono">{scanData.target}</span>
            </div>
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">Location</span>
              <span className="text-slate-200">{scanData.geolocation.city}, {scanData.geolocation.country}</span>
            </div>
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">ISP</span>
              <span className="text-slate-200">{scanData.geolocation.isp}</span>
            </div>
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">Registrar</span>
              <span className="text-slate-200">{scanData.whois_summary.registrar}</span>
            </div>
            <div className="flex justify-between pb-1">
              <span className="text-slate-500">Open Ports</span>
              <span className="text-slate-200">{scanData.open_ports.length} Detected</span>
            </div>
          </div>
        </div>

        {/* Port Distribution Chart */}
        <div className="md:col-span-4 bg-slate-800 rounded-xl p-6 border border-slate-700">
           <h2 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Activity className="text-blue-400" /> Service Distribution
          </h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} />
                <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="md:col-span-8 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-semibold text-slate-300 mb-6 flex items-center gap-2">
            <AlertTriangle className="text-blue-400" /> Identified Vulnerabilities
          </h2>
          <div className="space-y-4">
            {analysis.vulnerabilities.map((vuln, idx) => {
               const severityColors = {
                 'Critical': 'bg-red-500/10 text-red-500 border-red-500/20',
                 'High': 'bg-orange-500/10 text-orange-500 border-orange-500/20',
                 'Medium': 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
                 'Low': 'bg-blue-500/10 text-blue-500 border-blue-500/20',
               };
               const colorClass = severityColors[vuln.severity] || severityColors['Low'];

               return (
                <div key={idx} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/50">
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <h3 className="font-semibold text-slate-200">{vuln.name}</h3>
                      {vuln.cve && <span className="text-xs text-slate-500 font-mono mt-1 block">{vuln.cve}</span>}
                    </div>
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${colorClass}`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <p className="text-slate-400 text-sm mb-3">{vuln.description}</p>
                  <div className="bg-slate-800 p-3 rounded border border-slate-700">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-1">Mitigation</span>
                    <p className="text-slate-300 text-sm">{vuln.mitigation}</p>
                  </div>
                </div>
               );
            })}
            {analysis.vulnerabilities.length === 0 && (
              <div className="text-center py-8 text-slate-500">
                <CheckCircle className="mx-auto mb-3 text-green-500" size={32} />
                <p>No significant vulnerabilities detected.</p>
              </div>
            )}
          </div>
        </div>

        {/* Recommendations */}
        <div className="md:col-span-4 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-semibold text-slate-300 mb-6 flex items-center gap-2">
            <FileText className="text-blue-400" /> Recommendations
          </h2>
          <ul className="space-y-4">
            {analysis.recommendations.map((rec, idx) => (
              <li key={idx} className="flex gap-3 text-sm text-slate-300">
                <div className="shrink-0 w-6 h-6 rounded-full bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold text-xs">
                  {idx + 1}
                </div>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
        
        {/* Active Toolchain Section */}
        <div className="md:col-span-12 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-semibold text-slate-300 mb-6 flex items-center gap-2">
            <Settings className="text-blue-400" /> Active Security Toolchain
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {tools.map((tool, idx) => (
              <div key={idx} className="bg-slate-900/50 border border-slate-700/50 p-4 rounded-lg flex flex-col items-center text-center transition-all hover:border-blue-500/30 hover:bg-slate-800">
                 <div className="w-10 h-10 rounded-full bg-blue-500/10 text-blue-400 flex items-center justify-center mb-2 font-mono font-bold text-xs">
                   {tool.name.substring(0, 2).toUpperCase()}
                 </div>
                 <h3 className="font-semibold text-slate-200 text-sm">{tool.name}</h3>
                 <p className="text-xs text-slate-500 mt-1">{tool.type}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};