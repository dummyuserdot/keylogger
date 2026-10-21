import React, { useState } from 'react';
import { Play, ShieldAlert, Cpu, Terminal, CheckCircle2, AlertTriangle, FileCode, Sliders } from 'lucide-react';
import { DetectedThreat } from '../types';

interface SimulationTabProps {
  onInjectThreat: (threat: DetectedThreat) => void;
  onSimulateConfigTamper: () => void;
}

export const SimulationTab: React.FC<SimulationTabProps> = ({
  onInjectThreat,
  onSimulateConfigTamper,
}) => {
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);

  const simulateLowLevelHook = () => {
    setActiveSimulation('hook');
    const newThreat: DetectedThreat = {
      threatId: `sim-hook-${Date.now()}`,
      processName: 'svchost_klog.exe',
      pid: Math.floor(Math.random() * 4000) + 5000,
      executablePath: 'C:\\Users\\Victim\\AppData\\Local\\Temp\\svchost_klog.exe',
      detectedAt: new Date().toISOString(),
      severity: 'CRITICAL',
      confidenceScore: 96,
      isConfirmed: true,
      verdict: 'CONFIRMED_KEYLOGGER_THREAT',
      indicators: [
        {
          category: 'KEYBOARD_HOOK_API',
          severity: 'HIGH',
          title: 'Active WH_KEYBOARD_LL (Type 13) Global Hook',
          description: 'SetWindowsHookExW installed low-level keyboard hook intercepting physical WM_KEYDOWN/WM_KEYUP messages before dispatch to target application.',
          weight: 45,
        },
        {
          category: 'SUSPICIOUS_EXECUTABLE_PATH',
          severity: 'HIGH',
          title: 'Dropped Binary Running from %TEMP%',
          description: 'Process executes from transient user temporary folder.',
          weight: 30,
        },
        {
          category: 'PROCESS_MASQUERADING',
          severity: 'CRITICAL',
          title: 'Windows System Host Masquerading',
          description: 'Process mimics svchost.exe outside of Windows\\System32.',
          weight: 35,
        },
      ],
      notes: 'Simulated stealth keylogger demonstrating multi-indicator correlation.',
    };
    onInjectThreat(newThreat);
    setTimeout(() => setActiveSimulation(null), 800);
  };

  const simulateRawInputSniffer = () => {
    setActiveSimulation('raw');
    const newThreat: DetectedThreat = {
      threatId: `sim-raw-${Date.now()}`,
      processName: 'telemetry_agent.exe',
      pid: Math.floor(Math.random() * 3000) + 4000,
      executablePath: 'C:\\ProgramData\\WindowsDiagnostics\\telemetry_agent.exe',
      detectedAt: new Date().toISOString(),
      severity: 'HIGH',
      confidenceScore: 82,
      isConfirmed: false,
      verdict: 'SUSPICIOUS_INDICATOR_UNCONFIRMED',
      indicators: [
        {
          category: 'RAW_INPUT_CAPTURE',
          severity: 'HIGH',
          title: 'Raw Input Sink Listener (RIDEV_INPUTSINK)',
          description: 'Subscribed to background Raw Input messages for Generic Desktop Keyboard HID device without requiring active window focus.',
          weight: 40,
        },
        {
          category: 'ASYNC_KEYSTATE_POLLING',
          severity: 'MEDIUM',
          title: 'GetAsyncKeyState Polling Loop',
          description: 'Thread executing tight loop querying physical key state at 100+ queries/second.',
          weight: 25,
        },
      ],
      notes: 'Simulated raw input background sniffer. Requires analyst review before termination.',
    };
    onInjectThreat(newThreat);
    setTimeout(() => setActiveSimulation(null), 800);
  };

  const simulateLegitimateTool = () => {
    setActiveSimulation('benign');
    const newThreat: DetectedThreat = {
      threatId: `sim-benign-${Date.now()}`,
      processName: 'powertoys.keyboardmanagerengine.exe',
      pid: Math.floor(Math.random() * 2000) + 2000,
      executablePath: 'C:\\Program Files\\PowerToys\\PowerToys.KeyboardManagerEngine.exe',
      detectedAt: new Date().toISOString(),
      severity: 'LOW',
      confidenceScore: 15,
      isConfirmed: false,
      verdict: 'BENIGN_OVERLAY_UTILITY',
      isWhitelisted: true,
      indicators: [
        {
          category: 'KEYBOARD_HOOK_API',
          severity: 'LOW',
          title: 'WH_KEYBOARD_LL Detected (Legitimate Utility Whitelisted)',
          description: 'Low-level keyboard hook used for Microsoft PowerToys custom key remapping. Valid digital signature and system path verified.',
          weight: 10,
        },
      ],
      notes: 'Anti-false-positive mechanism successfully recognized legitimate utility.',
    };
    onInjectThreat(newThreat);
    setTimeout(() => setActiveSimulation(null), 800);
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Interactive Threat Sandbox &amp; Heuristic Validation</span>
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
          Test KeySentinel's detection rules by simulating adversarial techniques. Observe how the engine correlates
          low-level keyboard hooks, execution locations, process masquerading, and anti-false-positive filtering.
        </p>
      </div>

      {/* Simulation Triggers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Test 1: Low-Level Hook in Temp */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-colors">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-red-400 flex items-center space-x-1.5 font-mono">
                <ShieldAlert className="w-4 h-4" />
                <span>ATTACK SIMULATION: WH_KEYBOARD_LL</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                CRITICAL
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white mt-2">
              Low-Level Hook Keylogger in %TEMP%
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Injects a process executing from AppData\Local\Temp named <code className="text-cyan-300">svchost_klog.exe</code> installing a global WH_KEYBOARD_LL hook.
            </p>
          </div>
          <button
            onClick={simulateLowLevelHook}
            disabled={activeSimulation === 'hook'}
            className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-500 text-white flex items-center justify-center space-x-2 transition-all shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{activeSimulation === 'hook' ? 'Injecting Threat...' : 'Inject Rogue Keylogger'}</span>
          </button>
        </div>

        {/* Test 2: Raw Input Sniffer */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-colors">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-orange-400 flex items-center space-x-1.5 font-mono">
                <AlertTriangle className="w-4 h-4" />
                <span>ATTACK SIMULATION: RAW INPUT SINK</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800">
                HIGH SEVERITY
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white mt-2">
              Background Raw Input Sniffer (RIDEV_INPUTSINK)
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Injects an unverified service registering for Raw Input keyboard packets with GetAsyncKeyState polling.
            </p>
          </div>
          <button
            onClick={simulateRawInputSniffer}
            disabled={activeSimulation === 'raw'}
            className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-bold bg-orange-600 hover:bg-orange-500 text-white flex items-center justify-center space-x-2 transition-all shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{activeSimulation === 'raw' ? 'Injecting...' : 'Inject Raw Input Sniffer'}</span>
          </button>
        </div>

        {/* Test 3: Anti-False-Positive Filter Test */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-colors">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 flex items-center space-x-1.5 font-mono">
                <CheckCircle2 className="w-4 h-4" />
                <span>ANTI-FALSE-POSITIVE TEST</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                BENIGN
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white mt-2">
              Microsoft PowerToys Keyboard Remapper
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Demonstrates anti-false-positive filtering: Known legitimate tools using low-level keyboard hooks are recognized and whitelisted.
            </p>
          </div>
          <button
            onClick={simulateLegitimateTool}
            disabled={activeSimulation === 'benign'}
            className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center justify-center space-x-2 transition-all shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{activeSimulation === 'benign' ? 'Evaluating...' : 'Simulate PowerToys Overlay'}</span>
          </button>
        </div>

        {/* Test 4: Configuration File Tampering */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-colors">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-cyan-400 flex items-center space-x-1.5 font-mono">
                <Sliders className="w-4 h-4" />
                <span>TAMPER RESISTANCE TEST</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                INTEGRITY AUDIT
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white mt-2">
              Tamper Protected Policy JSON
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Simulates unauthorized modification of <code className="text-cyan-300">keysentinel_policy.json</code> to trigger cryptographic hash mismatch alerts.
            </p>
          </div>
          <button
            onClick={onSimulateConfigTamper}
            className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center justify-center space-x-2 transition-all shadow-md"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Simulate File Tampering</span>
          </button>
        </div>
      </div>
    </div>
  );
};
