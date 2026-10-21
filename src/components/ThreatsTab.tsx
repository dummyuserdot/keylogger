import React, { useState } from 'react';
import { Shield, ShieldAlert, AlertTriangle, Eye, Ban, CheckCircle2, RefreshCw, Filter, Search } from 'lucide-react';
import { DetectedThreat } from '../types';

interface ThreatsTabProps {
  threats: DetectedThreat[];
  onSelectThreat: (threat: DetectedThreat) => void;
  onQuarantine: (threatId: string) => void;
  onWhitelist: (threatId: string) => void;
  onScanNow: () => void;
  isScanning: boolean;
}

export const ThreatsTab: React.FC<ThreatsTabProps> = ({
  threats,
  onSelectThreat,
  onQuarantine,
  onWhitelist,
  onScanNow,
  isScanning,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredThreats = threats.filter((t) => {
    if (filterSeverity !== 'ALL' && t.severity !== filterSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        t.processName.toLowerCase().includes(q) ||
        t.executablePath.toLowerCase().includes(q) ||
        t.verdict.toLowerCase().includes(q) ||
        t.pid.toString().includes(q)
      );
    }
    return true;
  });

  const criticalCount = threats.filter((t) => t.severity === 'CRITICAL').length;
  const highCount = threats.filter((t) => t.severity === 'HIGH').length;
  const whitelistedCount = threats.filter((t) => t.isWhitelisted).length;

  return (
    <div className="space-y-6">
      {/* Top Telemetry Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] font-mono font-semibold uppercase text-slate-400 block">
            Critical Keyloggers
          </span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className="text-2xl font-bold font-mono text-red-400">{criticalCount}</span>
            <span className="text-xs text-red-400/80">Confirmed Threats</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] font-mono font-semibold uppercase text-slate-400 block">
            Suspicious Hooks
          </span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className="text-2xl font-bold font-mono text-orange-400">{highCount}</span>
            <span className="text-xs text-orange-400/80">Unconfirmed</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] font-mono font-semibold uppercase text-slate-400 block">
            Whitelisted Overlays
          </span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className="text-2xl font-bold font-mono text-emerald-400">{whitelistedCount}</span>
            <span className="text-xs text-emerald-400/80">Anti-False-Positive</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-[11px] font-mono font-semibold uppercase text-slate-400 block">
            Subsystem Defense
          </span>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className="text-2xl font-bold font-mono text-cyan-400">ACTIVE</span>
            <span className="text-xs text-cyan-400/80">WH_KEYBOARD_LL</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by name, PID, path..."
              className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            {['ALL', 'CRITICAL', 'HIGH', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 text-[11px] font-semibold rounded ${
                  filterSeverity === sev
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={onScanNow}
          disabled={isScanning}
          className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-colors flex items-center justify-center space-x-2 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? 'Inspecting Processes...' : 'Run Security Scan'}</span>
        </button>
      </div>

      {/* Threats Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] uppercase font-mono text-slate-400">
                <th className="py-3 px-4">PID</th>
                <th className="py-3 px-4">Process Name</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Verdict &amp; Indicators</th>
                <th className="py-3 px-4">Executable Path</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-xs">
              {filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                    No matching threat indicators detected.
                  </td>
                </tr>
              ) : (
                filteredThreats.map((threat) => (
                  <tr
                    key={threat.threatId}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      threat.quarantined ? 'opacity-50 line-through' : ''
                    }`}
                  >
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {threat.pid > 0 ? threat.pid : 'System'}
                    </td>
                    <td className="py-3.5 px-4 font-medium text-white flex items-center space-x-2">
                      <span>{threat.processName}</span>
                      {threat.isWhitelisted && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          Whitelisted
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        threat.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                        threat.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        threat.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-blue-950 text-blue-400 border border-blue-800'
                      }`}>
                        {threat.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-semibold">
                      <div className="flex items-center space-x-1.5">
                        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              threat.confidenceScore > 80 ? 'bg-red-500' :
                              threat.confidenceScore > 50 ? 'bg-orange-500' :
                              'bg-emerald-500'
                            }`}
                            style={{ width: `${threat.confidenceScore}%` }}
                          />
                        </div>
                        <span className="text-[11px] text-slate-300">{threat.confidenceScore}%</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-200">
                        {threat.isConfirmed ? (
                          <span className="text-red-400 flex items-center space-x-1">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span>Confirmed Keylogger</span>
                          </span>
                        ) : threat.isWhitelisted ? (
                          <span className="text-emerald-400">Benign Overlay</span>
                        ) : (
                          <span className="text-amber-400">Suspicious Indicator</span>
                        )}
                      </div>
                      <span className="text-[11px] text-slate-400">
                        {threat.indicators.length} indicator(s) identified
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px] max-w-xs truncate" title={threat.executablePath}>
                      {threat.executablePath}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="inline-flex items-center space-x-1">
                        <button
                          onClick={() => onSelectThreat(threat)}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 transition-colors"
                          title="Inspect Evidence"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        {!threat.isWhitelisted && (
                          <button
                            onClick={() => onWhitelist(threat.threatId)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-400 transition-colors"
                            title="Add to Whitelist"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {!threat.quarantined && threat.pid > 0 && (
                          <button
                            onClick={() => onQuarantine(threat.threatId)}
                            className="p-1.5 rounded-lg bg-red-950/80 hover:bg-red-900 text-red-400 transition-colors"
                            title="Neutralize / Terminate Process"
                          >
                            <Ban className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
