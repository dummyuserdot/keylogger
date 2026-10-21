import React, { useState } from 'react';
import { Header } from './components/Header';
import { ThreatsTab } from './components/ThreatsTab';
import { SimulationTab } from './components/SimulationTab';
import { AuditLogTab } from './components/AuditLogTab';
import { CodeExplorerTab } from './components/CodeExplorerTab';
import { DeploymentGuideTab } from './components/DeploymentGuideTab';
import { AuthModal } from './components/AuthModal';
import { EvidenceModal } from './components/EvidenceModal';
import { INITIAL_THREATS, INITIAL_AUDIT_LOGS } from './data/initialData';
import { DetectedThreat, SecurityEvent } from './types';
import { Shield, ShieldAlert, Power, RotateCcw, Lock, CheckCircle2, Terminal } from 'lucide-react';

export default function App() {
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [threats, setThreats] = useState<DetectedThreat[]>(INITIAL_THREATS);
  const [logs, setLogs] = useState<SecurityEvent[]>(INITIAL_AUDIT_LOGS);
  const [activeTab, setActiveTab] = useState('threats');
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [selectedThreatForEvidence, setSelectedThreatForEvidence] = useState<DetectedThreat | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isShutdown, setIsShutdown] = useState(false);

  const addLog = (
    category: SecurityEvent['category'],
    action: string,
    severity: SecurityEvent['severity'],
    details: Record<string, any>,
    success: boolean = true
  ) => {
    const newLog: SecurityEvent = {
      id: `log-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date().toISOString(),
      category,
      action,
      severity,
      success,
      details,
    };
    setLogs((prev) => [newLog, ...prev]);
  };

  const handleToggleMonitoring = () => {
    const nextState = !isMonitoring;
    setIsMonitoring(nextState);
    addLog(
      'MONITORING_ENGINE',
      nextState ? 'MONITORING_ENGINE_RESUMED' : 'MONITORING_ENGINE_PAUSED',
      'INFO',
      { initiatedBy: 'Operator', state: nextState ? 'ACTIVE' : 'PAUSED' }
    );
  };

  const handleScanNow = () => {
    setIsScanning(true);
    addLog('MONITORING_ENGINE', 'MANUAL_FORENSIC_SCAN_INITIATED', 'INFO', {
      scanTargets: ['WH_KEYBOARD_LL', 'WH_KEYBOARD', 'RIDEV_INPUTSINK', 'ProcessPaths', 'RegistryRun'],
    });

    setTimeout(() => {
      setIsScanning(false);
      addLog('MONITORING_ENGINE', 'MANUAL_SCAN_COMPLETED', 'INFO', {
        activeProcessesScanned: 148,
        threatsIdentified: threats.length,
      });
    }, 700);
  };

  const handleAuthorizedShutdown = () => {
    setIsAuthModalOpen(false);
    setIsMonitoring(false);
    setIsShutdown(true);

    addLog(
      'APPLICATION_LIFECYCLE',
      'APPLICATION_SHUTDOWN_AUTHORIZED',
      'INFO',
      {
        authorizedBy: 'Administrator',
        prototypeCredentialMatched: true,
        action: 'GRACEFUL_SHUTDOWN',
      },
      true
    );
  };

  const handleRestartMonitor = () => {
    setIsShutdown(false);
    setIsMonitoring(true);
    addLog('APPLICATION_LIFECYCLE', 'APPLICATION_REBOOTED', 'INFO', {
      status: 'REINITIALIZED_BY_ADMIN',
    });
  };

  const handleRecordFailedAttempt = (attemptCount: number) => {
    addLog(
      'AUTHENTICATION',
      'ADMIN_AUTHENTICATION_FAILURE',
      attemptCount >= 5 ? 'CRITICAL' : 'WARNING',
      {
        attemptCount,
        source: 'GUI_SHUTDOWN_GATE',
        enteredPassword: '[REDACTED]',
        lockoutTriggered: attemptCount >= 5,
      },
      false
    );
  };

  const handleQuarantine = (threatId: string) => {
    setThreats((prev) =>
      prev.map((t) => (t.threatId === threatId ? { ...t, quarantined: true } : t))
    );
    const target = threats.find((t) => t.threatId === threatId);
    if (target) {
      addLog('SUSPICIOUS_PROCESS', 'PROCESS_QUARANTINED_TERMINATED', 'WARNING', {
        pid: target.pid,
        processName: target.processName,
        action: 'TERMINATE_SIGNAL_SENT',
      });
    }
  };

  const handleWhitelist = (threatId: string) => {
    setThreats((prev) =>
      prev.map((t) => (t.threatId === threatId ? { ...t, isWhitelisted: true, severity: 'LOW' } : t))
    );
    const target = threats.find((t) => t.threatId === threatId);
    if (target) {
      addLog('SUSPICIOUS_PROCESS', 'PROCESS_ADDED_TO_WHITELIST', 'INFO', {
        pid: target.pid,
        processName: target.processName,
      });
    }
  };

  const handleInjectThreat = (newThreat: DetectedThreat) => {
    setThreats((prev) => [newThreat, ...prev]);
    addLog('SUSPICIOUS_PROCESS', 'KEYLOGGER_THREAT_DETECTED', newThreat.severity, {
      pid: newThreat.pid,
      processName: newThreat.processName,
      verdict: newThreat.verdict,
      confidenceScore: newThreat.confidenceScore,
    });
  };

  const handleSimulateConfigTamper = () => {
    const tamperThreat: DetectedThreat = {
      threatId: `threat-tamper-${Date.now()}`,
      processName: 'System / File Integrity',
      pid: 0,
      executablePath: 'C:\\ProgramData\\KeySentinel\\config\\keysentinel_policy.json',
      detectedAt: new Date().toISOString(),
      severity: 'CRITICAL',
      confidenceScore: 98,
      isConfirmed: true,
      verdict: 'CONFIGURATION_TAMPER_DETECTED',
      indicators: [
        {
          category: 'CONFIGURATION_TAMPER',
          severity: 'CRITICAL',
          title: 'Protected Configuration Hash Mismatch',
          description: 'Cryptographic SHA-256 integrity baseline failed. Unauthorized modification to policy file detected.',
          weight: 50,
        },
      ],
      notes: 'Potential adversary attempt to disable WH_KEYBOARD_LL hook detection.',
    };
    handleInjectThreat(tamperThreat);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Top Header */}
      <Header
        isMonitoring={isMonitoring && !isShutdown}
        onToggleMonitoring={handleToggleMonitoring}
        onOpenAuthModal={() => setIsAuthModalOpen(true)}
        onScanNow={handleScanNow}
        threatCount={threats.filter((t) => !t.quarantined && !t.isWhitelisted).length}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Graceful Shutdown Screen */}
        {isShutdown ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 max-w-xl mx-auto my-12 text-center space-y-5 shadow-2xl animate-fade-in">
            <div className="w-16 h-16 rounded-2xl bg-red-950/60 border border-red-800 text-red-400 mx-auto flex items-center justify-center">
              <Power className="w-8 h-8" />
            </div>

            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-red-400 bg-red-950/80 px-2 py-0.5 rounded border border-red-800/80">
                Authorized Shutdown Completed
              </span>
              <h2 className="text-xl font-bold text-white mt-2">
                KeySentinel Monitor Stopped
              </h2>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                Administrator authentication was verified with password{' '}
                <code className="text-cyan-400 font-mono">27254</code>. Background threads,
                low-level detection callbacks, and OS resources have been cleanly released.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-left font-mono text-xs text-slate-300 space-y-1.5">
              <div className="text-emerald-400 font-bold flex items-center space-x-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>Clean Shutdown Checklist:</span>
              </div>
              <div className="text-slate-400 pl-5">• Thread KeySentinel-MonitorWorker joined: OK</div>
              <div className="text-slate-400 pl-5">• Hook callback handles unregistered: OK</div>
              <div className="text-slate-400 pl-5">• Audit event recorded to disk: OK</div>
            </div>

            <button
              onClick={handleRestartMonitor}
              className="px-6 py-2.5 rounded-xl text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-lg shadow-cyan-600/20 inline-flex items-center space-x-2"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Restart KeySentinel Security Monitor</span>
            </button>
          </div>
        ) : (
          <div>
            {/* Active Tab View */}
            {activeTab === 'threats' && (
              <ThreatsTab
                threats={threats}
                onSelectThreat={(t) => setSelectedThreatForEvidence(t)}
                onQuarantine={handleQuarantine}
                onWhitelist={handleWhitelist}
                onScanNow={handleScanNow}
                isScanning={isScanning}
              />
            )}

            {activeTab === 'simulator' && (
              <SimulationTab
                onInjectThreat={handleInjectThreat}
                onSimulateConfigTamper={handleSimulateConfigTamper}
              />
            )}

            {activeTab === 'auth' && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-2xl mx-auto space-y-6">
                <div className="flex items-center space-x-3">
                  <div className="p-3 rounded-xl bg-red-950/60 border border-red-800 text-red-400">
                    <Lock className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">
                      Administrator Authentication &amp; Shutdown Workflow
                    </h3>
                    <p className="text-xs text-slate-400">
                      Requirement 3: Configured prototype administrator credential
                    </p>
                  </div>
                </div>

                <div className="bg-cyan-950/40 border border-cyan-800/60 rounded-lg p-4 space-y-2 text-xs text-cyan-200">
                  <div className="font-bold text-cyan-300">Configured Local Prototype Credential:</div>
                  <div className="font-mono text-base bg-cyan-900/60 p-2 rounded text-center tracking-widest text-white font-bold border border-cyan-700">
                    27254
                  </div>
                  <p className="text-[11px] text-cyan-300/80 leading-relaxed">
                    Test entering correct or incorrect passwords in the dialog to verify:
                    graceful shutdown on match, continued monitoring on rejection, failed attempt tracking without credential logging, and 30-second lockout on 5 consecutive failures.
                  </p>
                </div>

                <div className="text-center pt-2">
                  <button
                    onClick={() => setIsAuthModalOpen(true)}
                    className="px-6 py-2.5 rounded-xl text-xs font-bold bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30 transition-all inline-flex items-center space-x-2"
                  >
                    <Lock className="w-4 h-4" />
                    <span>Open Authentication Dialog</span>
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'logs' && <AuditLogTab logs={logs} />}

            {activeTab === 'code' && <CodeExplorerTab />}

            {activeTab === 'guide' && <DeploymentGuideTab />}
          </div>
        )}
      </main>

      {/* Authentication Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthorizedShutdown={handleAuthorizedShutdown}
        onRecordFailedAttempt={handleRecordFailedAttempt}
      />

      {/* Threat Evidence Deep-Dive Modal */}
      <EvidenceModal
        threat={selectedThreatForEvidence}
        onClose={() => setSelectedThreatForEvidence(null)}
        onQuarantine={handleQuarantine}
        onWhitelist={handleWhitelist}
      />

      {/* Bottom Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <p>KeySentinel — Windows Keylogger Detection &amp; Security Monitor (Windows 10 &amp; 11 Compatible)</p>
      </footer>
    </div>
  );
}
