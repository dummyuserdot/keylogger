import React from 'react';
import { X, ShieldAlert, AlertTriangle, FileCode, Cpu, CheckCircle2, Ban } from 'lucide-react';
import { DetectedThreat } from '../types';

interface EvidenceModalProps {
  threat: DetectedThreat | null;
  onClose: () => void;
  onQuarantine: (threatId: string) => void;
  onWhitelist: (threatId: string) => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  threat,
  onClose,
  onQuarantine,
  onWhitelist,
}) => {
  if (!threat) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="bg-slate-800/90 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${
              threat.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
              threat.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
              threat.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
              'bg-blue-500/20 text-blue-400'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-white font-mono">{threat.processName}</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  PID {threat.pid > 0 ? threat.pid : 'N/A'}
                </span>
              </div>
              <p className="text-xs text-slate-400">Forensic Threat Evidence &amp; Anti-False-Positive Assessment</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-700/50 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Verdict Banner */}
          <div className={`p-4 rounded-xl border flex items-center justify-between ${
            threat.isConfirmed
              ? 'bg-red-950/30 border-red-800/60 text-red-200'
              : threat.isWhitelisted
              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
              : 'bg-amber-950/30 border-amber-800/60 text-amber-200'
          }`}>
            <div>
              <span className="text-[10px] font-mono font-bold tracking-wider uppercase block opacity-80">
                Threat Classification
              </span>
              <span className="text-base font-bold tracking-tight">{threat.verdict}</span>
              <p className="text-xs mt-1 text-slate-300">{threat.notes}</p>
            </div>
            <div className="text-right">
              <span className="text-[10px] uppercase font-mono block opacity-80">Confidence</span>
              <span className="text-2xl font-black font-mono">{threat.confidenceScore}%</span>
            </div>
          </div>

          {/* Process Metadata */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/70">
              <span className="text-slate-400 font-medium block">Executable Path</span>
              <span className="text-slate-200 font-mono break-all mt-1 block">{threat.executablePath}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/70">
              <span className="text-slate-400 font-medium block">Detection Timestamp</span>
              <span className="text-slate-200 font-mono mt-1 block">{threat.detectedAt}</span>
            </div>
          </div>

          {/* Indicators List */}
          <div>
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
              Observed Forensic Indicators ({threat.indicators.length})
            </h4>
            <div className="space-y-3">
              {threat.indicators.map((ind, i) => (
                <div key={i} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200 flex items-center space-x-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{ind.title}</span>
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold ${
                      ind.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                      ind.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                      ind.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      'bg-blue-950 text-blue-400 border border-blue-800'
                    }`}>
                      {ind.severity} (+{ind.weight} pts)
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{ind.description}</p>
                  {ind.evidenceData && Object.keys(ind.evidenceData).length > 0 && (
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                      <pre>{JSON.stringify(ind.evidenceData, null, 2)}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="bg-slate-950/90 px-6 py-4 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition-colors"
          >
            Dismiss
          </button>
          <div className="flex items-center space-x-2">
            {!threat.isWhitelisted && (
              <button
                onClick={() => {
                  onWhitelist(threat.threatId);
                  onClose();
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center space-x-1"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Whitelist</span>
              </button>
            )}
            {!threat.quarantined && threat.pid > 0 && (
              <button
                onClick={() => {
                  onQuarantine(threat.threatId);
                  onClose();
                }}
                className="px-3.5 py-1.5 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-500 text-white shadow-md transition-colors flex items-center space-x-1"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>Neutralize Process</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
