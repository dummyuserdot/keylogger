import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Play, Pause, Search, Power, Terminal, Lock } from 'lucide-react';

interface HeaderProps {
  isMonitoring: boolean;
  onToggleMonitoring: () => void;
  onOpenAuthModal: () => void;
  onScanNow: () => void;
  threatCount: number;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  isMonitoring,
  onToggleMonitoring,
  onOpenAuthModal,
  onScanNow,
  threatCount,
  activeTab,
  setActiveTab,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40 backdrop-blur-md bg-opacity-95">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Identity */}
          <div className="flex items-center space-x-3">
            <div className="relative">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                isMonitoring 
                  ? 'bg-gradient-to-tr from-cyan-600 to-emerald-500 shadow-lg shadow-cyan-500/20' 
                  : 'bg-slate-800 border border-slate-700'
              }`}>
                {isMonitoring ? (
                  <ShieldCheck className="w-6 h-6 text-white animate-pulse" />
                ) : (
                  <ShieldAlert className="w-6 h-6 text-amber-400" />
                )}
              </div>
              {isMonitoring && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                </span>
              )}
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-bold text-white tracking-tight">KeySentinel</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  Windows 10/11
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                  Elevated
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Defensive Keylogger Detection &amp; Keystroke Subsystem Monitor
              </p>
            </div>
          </div>

          {/* Action Bar */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {/* Quick Scan */}
            <button
              onClick={onScanNow}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors shadow-sm"
              title="Execute immediate process and hook inspection"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Scan Now</span>
            </button>

            {/* Toggle Monitoring */}
            <button
              onClick={onToggleMonitoring}
              className={`inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors shadow-sm ${
                isMonitoring
                  ? 'bg-slate-800 hover:bg-slate-700 text-amber-400 border-slate-700'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500'
              }`}
            >
              {isMonitoring ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Pause Monitor</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Resume Monitor</span>
                </>
              )}
            </button>

            {/* Admin Shutdown Gate (Enforces password 27254) */}
            <button
              onClick={onOpenAuthModal}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-bold rounded-lg bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-800/80 transition-all shadow-sm hover:shadow-red-900/30"
              title="Admin Authentication Required to Shutdown (Password: 27254)"
            >
              <Lock className="w-3.5 h-3.5 text-red-400" />
              <span>Admin Exit</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 sm:space-x-4 overflow-x-auto border-t border-slate-800/80 py-2 scrollbar-none">
          {[
            { id: 'threats', label: 'Threats & Hooks', badge: threatCount > 0 ? threatCount : undefined },
            { id: 'simulator', label: 'Threat Sandbox' },
            { id: 'auth', label: 'Admin Authentication' },
            { id: 'logs', label: 'Audit Log' },
            { id: 'code', label: 'Python Code & Tests' },
            { id: 'guide', label: 'Windows Hardening' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors flex items-center space-x-1.5 ${
                activeTab === tab.id
                  ? 'bg-cyan-500/10 text-cyan-400 font-semibold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span className="inline-flex items-center px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
};
