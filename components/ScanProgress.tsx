import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, Database, Activity, Search } from 'lucide-react';
import { LogEntry } from '../types';

interface ScanProgressProps {
  logs: LogEntry[];
  currentModule: string;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ logs, currentModule }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const steps = [
    { id: '1', title: 'Input Acquisition', icon: Search, completed: true },
    { id: '2', title: 'Data Collection', icon: Database, active: currentModule === 'Data Collection', completed: logs.some(l => l.module === 'Data Collection' && l.message.includes('complete')) },
    { id: '3', title: 'Feature Extraction', icon: Activity, active: currentModule === 'Feature Extraction', completed: logs.some(l => l.module === 'Feature Extraction' && l.message.includes('complete')) },
    { id: '4', title: 'Risk Analysis', icon: Shield, active: currentModule === 'Risk Analysis', completed: false },
  ];

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8">
      {/* Progress Steps */}
      <div className="flex justify-between items-center bg-slate-800/50 p-6 rounded-xl border border-slate-700">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isActive = step.active;
          const isCompleted = step.completed;
          
          return (
            <div key={step.id} className="flex flex-col items-center relative z-10">
               <div className={`w-12 h-12 rounded-full flex items-center justify-center mb-3 transition-all duration-500 ${
                 isActive ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/30' : 
                 isCompleted ? 'bg-green-500 text-slate-900' : 'bg-slate-700 text-slate-400'
               }`}>
                 <Icon size={20} />
               </div>
               <span className={`text-sm font-medium ${isActive || isCompleted ? 'text-white' : 'text-slate-500'}`}>
                 {step.title}
               </span>
               {idx !== steps.length - 1 && (
                 <div className="hidden md:block absolute top-6 left-1/2 w-full h-0.5 -z-10">
                    <div className={`h-full w-[200%] ${isCompleted ? 'bg-green-500/50' : 'bg-slate-700'}`}></div>
                 </div>
               )}
            </div>
          );
        })}
      </div>

      {/* Terminal Output */}
      <div className="bg-black/90 rounded-lg overflow-hidden border border-slate-700 shadow-2xl font-mono text-sm">
        <div className="bg-slate-800 px-4 py-2 flex items-center gap-2 border-b border-slate-700">
          <Terminal size={14} className="text-slate-400" />
          <span className="text-slate-400">WebGuard_Console — Live Trace</span>
        </div>
        <div 
          ref={scrollRef}
          className="h-96 overflow-y-auto p-4 space-y-2"
        >
          {logs.map((log, idx) => (
            <div key={idx} className="flex gap-3 animate-fade-in">
              <span className="text-slate-500 shrink-0">
                [{new Date(log.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 } as any)}]
              </span>
              <span className={`
                ${log.type === 'info' ? 'text-blue-400' : ''}
                ${log.type === 'success' ? 'text-green-400' : ''}
                ${log.type === 'warning' ? 'text-yellow-400' : ''}
                ${log.type === 'error' ? 'text-red-500' : ''}
              `}>
                <span className="font-bold mr-2 text-slate-300">[{log.module}]</span>
                {log.message}
              </span>
            </div>
          ))}
          {currentModule !== 'Completed' && (
            <div className="flex gap-2 items-center text-slate-500 mt-2">
              <span className="animate-pulse">_</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};