import React from 'react';
import { 
  ResponsiveContainer, Tooltip, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { AlertTriangle, CheckCircle, ShieldAlert, Globe, Server, Activity, FileText, Unlock, FileDown } from 'lucide-react';
import { RawScanData, RiskAnalysisResult } from '../types';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

interface DashboardProps {
  scanData: RawScanData;
  analysis: RiskAnalysisResult;
  onReset: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ scanData, analysis, onReset }) => {
  // Data for Port Distribution
  const portStats = scanData.open_ports.reduce((acc, curr) => {
    const serviceName = curr.service || 'unknown';
    acc[serviceName] = (acc[serviceName] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const portChartData = Object.entries(portStats).map(([name, value]) => ({ name, value }));

  const handleGeneratePDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;

    // --- Header ---
    doc.setFillColor(15, 23, 42); // Slate-900 like
    doc.rect(0, 0, pageWidth, 40, 'F');
    
    doc.setFontSize(22);
    doc.setTextColor(255, 255, 255);
    doc.text("WebGuard Security Report", 14, 20);
    
    doc.setFontSize(10);
    doc.setTextColor(148, 163, 184); // Slate-400
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 30);
    
    // --- Target Information ---
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.text("Executive Summary", 14, 50);
    
    doc.setFontSize(10);
    doc.setTextColor(80, 80, 80);
    
    const infoX = 14;
    let infoY = 60;
    
    doc.text(`Target Host: ${scanData.target}`, infoX, infoY);
    doc.text(`ISP / Provider: ${scanData.geolocation?.isp || 'Unknown'}`, infoX, infoY + 6);
    doc.text(`Location: ${scanData.geolocation?.city || 'Unknown'}, ${scanData.geolocation?.country || 'Unknown'}`, infoX, infoY + 12);
    doc.text(`Total Open Ports: ${scanData.open_ports.length}`, infoX, infoY + 18);
    
    // --- Open Ports Table ---
    let yPos = 90;
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.text("Open Ports & Services Analysis", 14, yPos);
    yPos += 5;

    const portRows = scanData.open_ports.map(p => [
      p.port.toString(),
      p.service,
      p.version || 'Unknown',
      p.state,
      p.security_risk || 'None'
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [['Port', 'Service', 'Version', 'State', 'Risk']],
      body: portRows,
      theme: 'grid',
      headStyles: { fillColor: [51, 65, 85] }, // Slate-700
      alternateRowStyles: { fillColor: [241, 245, 249] },
      styles: { fontSize: 9 },
      columnStyles: {
        4: { fontStyle: 'bold' } // Risk column bold
      },
      didParseCell: (data) => {
        // Color code the Risk column
        if (data.section === 'body' && data.column.index === 4) {
          const risk = data.cell.raw as string;
          if (risk === 'Critical') data.cell.styles.textColor = [220, 38, 38];
          if (risk === 'High') data.cell.styles.textColor = [234, 88, 12];
          if (risk === 'Medium') data.cell.styles.textColor = [234, 179, 8];
        }
      }
    });

    // --- Vulnerabilities Table ---
    yPos = (doc as any).lastAutoTable.finalY + 15;
    
    // Check for page break needed
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }

    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text("Detected Vulnerabilities", 14, yPos);
    yPos += 5;

    if (analysis.vulnerabilities.length > 0) {
      const vulnRows = analysis.vulnerabilities.map(v => [
        v.severity,
        v.name,
        v.cve || 'N/A',
        v.description
      ]);

      autoTable(doc, {
        startY: yPos,
        head: [['Severity', 'Vulnerability', 'CVE', 'Description']],
        body: vulnRows,
        theme: 'grid',
        headStyles: { fillColor: [153, 27, 27] }, // Red-800
        styles: { fontSize: 8, cellPadding: 2 },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 20 },
          1: { cellWidth: 40 },
          2: { cellWidth: 30 },
          3: { cellWidth: 'auto' }
        }
      });
    } else {
      doc.setFontSize(10);
      doc.setTextColor(100);
      doc.text("No specific CVEs were identified for the detected services.", 14, yPos + 10);
    }

    // --- Recommendations ---
    yPos = (doc as any).lastAutoTable ? (doc as any).lastAutoTable.finalY + 15 : yPos + 20;

    // Check for page break
    if (yPos > 240) {
      doc.addPage();
      yPos = 20;
    }

    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text("Recommendations", 14, yPos);
    
    doc.setFontSize(10);
    doc.setTextColor(60);
    let recY = yPos + 10;
    
    analysis.recommendations.forEach((rec, idx) => {
      // Split text to fit page
      const splitText = doc.splitTextToSize(`${idx + 1}. ${rec}`, pageWidth - 30);
      doc.text(splitText, 14, recY);
      recY += (splitText.length * 5) + 2;
    });

    // Save
    doc.save(`WebGuard_Report_${scanData.target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
  };

  return (
    <div className="w-full max-w-7xl mx-auto space-y-6 pb-20">
      
      {/* Danger Alert Banner for Critical Risks */}
      {analysis.risk_level === 'Critical' && (
        <div className="bg-red-500/10 border border-red-500 rounded-xl p-4 flex items-center gap-4 animate-pulse">
          <div className="bg-red-500 text-white p-3 rounded-full shrink-0">
            <ShieldAlert size={24} />
          </div>
          <div>
            <h3 className="text-red-400 font-bold text-lg">CRITICAL SECURITY ALERT</h3>
            <p className="text-red-200 text-sm">
              Multiple critical vulnerabilities detected. Immediate action required. 
              The target contains exposed services (e.g., Telnet, RDP) or outdated software with known exploits.
            </p>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Nmap Security Report</h1>
          <div className="flex items-center gap-2 text-slate-400">
            <Globe size={16} />
            <span className="font-mono">{scanData.target}</span>
            <span className="mx-2">•</span>
            <span>{new Date().toLocaleDateString()}</span>
          </div>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={handleGeneratePDF}
            className="flex items-center gap-2 px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg font-medium transition-colors border border-slate-600"
          >
            <FileDown size={18} />
            <span className="hidden sm:inline">Export PDF</span>
          </button>
          <button 
            onClick={onReset}
            className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
          >
            New Scan
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        
        {/* Target Info */}
        <div className="md:col-span-6 bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col">
          <h2 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Server className="text-blue-400" /> Target Details
          </h2>
          <div className="space-y-4 text-sm flex-1">
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">Host</span>
              <span className="text-slate-200 font-mono truncate max-w-[150px]" title={scanData.target}>{scanData.target}</span>
            </div>
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">Location</span>
              <span className="text-slate-200 text-right">{scanData.geolocation?.city || 'Unknown'}, {scanData.geolocation?.country || 'Unknown'}</span>
            </div>
            <div className="flex justify-between border-b border-slate-700 pb-2">
              <span className="text-slate-500">Provider</span>
              <span className="text-slate-200 text-right">{scanData.geolocation?.isp || 'Unknown'}</span>
            </div>
             <div className="flex justify-between pb-1">
              <span className="text-slate-500">Open Ports</span>
              <span className="text-slate-200 font-bold">{scanData.open_ports.length}</span>
            </div>
            <div className="pt-2 mt-2 border-t border-slate-700">
               <span className="text-slate-500 block mb-1">Analysis Summary</span>
               <p className="text-slate-300 text-xs leading-relaxed">{analysis.summary}</p>
             </div>
          </div>
        </div>

        {/* Port Distribution Chart */}
        <div className="md:col-span-6 bg-slate-800 rounded-xl p-6 border border-slate-700 flex flex-col">
           <h2 className="text-lg font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Activity className="text-blue-400" /> Service Distribution
          </h2>
          {/* Replaced flex-1 min-h-[160px] with fixed height h-48 and w-full to prevent Recharts -1 dimension error */}
          <div className="h-48 w-full">
            {portChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={portChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                    itemStyle={{ color: '#f8fafc' }}
                    cursor={{fill: '#334155', opacity: 0.4}}
                  />
                  <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-500">
                <CheckCircle size={48} className="mb-2 opacity-50" />
                <p>No open services detected.</p>
              </div>
            )}
          </div>
        </div>

        {/* NEW NMAP PORT ANALYSIS SECTION */}
        <div className="md:col-span-12 bg-slate-800 rounded-xl p-6 border border-slate-700 overflow-hidden">
           <h2 className="text-lg font-semibold text-slate-300 mb-6 flex items-center gap-2">
            <Unlock className="text-blue-400" /> Nmap Port Security Analysis
          </h2>
          <div className="overflow-x-auto">
            {scanData.open_ports.length > 0 ? (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-700 text-slate-400 text-sm">
                    <th className="p-3 font-medium">Port / Proto</th>
                    <th className="p-3 font-medium">State</th>
                    <th className="p-3 font-medium">Service</th>
                    <th className="p-3 font-medium">Version</th>
                    <th className="p-3 font-medium">Risk Analysis</th>
                    <th className="p-3 font-medium">Risk Level</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {scanData.open_ports.map((port, idx) => {
                    const riskColors = {
                      'Critical': 'bg-red-500/20 text-red-400 border border-red-500/30',
                      'High': 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
                      'Medium': 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
                      'Low': 'bg-blue-500/10 text-blue-400',
                      'None': 'text-slate-500'
                    };
                    const riskStyle = riskColors[port.security_risk || 'None'] || riskColors['None'];

                    return (
                      <tr key={idx} className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                        <td className="p-3 font-mono text-slate-200">{port.port}/tcp</td>
                        <td className="p-3 text-green-400 font-medium">{port.state}</td>
                        <td className="p-3 text-slate-300">{port.service}</td>
                        <td className="p-3 text-slate-400 font-mono text-xs">{port.version || 'Unknown'}</td>
                        <td className="p-3 text-slate-400 max-w-md">{port.reason || 'Standard service detected.'}</td>
                        <td className="p-3">
                           <span className={`px-2 py-1 rounded text-xs font-semibold ${riskStyle}`}>
                             {port.security_risk}
                           </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="text-center py-8 text-slate-400">
                <CheckCircle className="mx-auto mb-3 text-green-500" size={32} />
                <p className="text-lg">No open ports were found on this target.</p>
                <p className="text-sm text-slate-500 mt-1">The host might be down, firewalled, or using non-standard ports not discovered during this scan.</p>
              </div>
            )}
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="md:col-span-8 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-lg font-semibold text-slate-300 mb-6 flex items-center gap-2">
            <AlertTriangle className="text-blue-400" /> Confirmed Vulnerabilities (CVE)
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
                <p>No CVEs associated with current open ports.</p>
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
        
      </div>
    </div>
  );
};