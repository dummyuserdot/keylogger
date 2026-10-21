export type ThreatSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IndicatorCategory =
  | 'KEYBOARD_HOOK_API'
  | 'RAW_INPUT_CAPTURE'
  | 'ASYNC_KEYSTATE_POLLING'
  | 'SUSPICIOUS_EXECUTABLE_PATH'
  | 'STARTUP_PERSISTENCE'
  | 'PROCESS_MASQUERADING'
  | 'HIDDEN_BACKGROUND_WINDOW'
  | 'CONFIGURATION_TAMPER';

export interface ThreatIndicator {
  category: IndicatorCategory;
  severity: ThreatSeverity;
  title: string;
  description: string;
  evidenceData?: Record<string, any>;
  weight: number;
}

export interface DetectedThreat {
  threatId: string;
  processName: string;
  pid: number;
  executablePath: string;
  detectedAt: string;
  severity: ThreatSeverity;
  confidenceScore: number;
  isConfirmed: boolean;
  verdict: string;
  indicators: ThreatIndicator[];
  isWhitelisted?: boolean;
  quarantined?: boolean;
  notes?: string;
}

export type EventCategory =
  | 'AUTHENTICATION'
  | 'SUSPICIOUS_PROCESS'
  | 'PERSISTENCE_TAMPER'
  | 'CONFIG_INTEGRITY'
  | 'SERVICE_CONTROL'
  | 'APPLICATION_LIFECYCLE'
  | 'MONITORING_ENGINE';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  category: EventCategory;
  action: string;
  severity: ThreatSeverity;
  success: boolean;
  details: Record<string, any>;
}

export interface StartupPersistenceEntry {
  id: string;
  name: string;
  command: string;
  location: string;
  isSuspicious: boolean;
  reason?: string;
}

export interface ScenarioTest {
  id: number;
  scenario: string;
  description: string;
  targetComponent: string;
  status: 'PASSED' | 'RUNNING' | 'PENDING' | 'FAILED';
  executionTimeMs: number;
  details: string;
}

export interface PythonSourceFile {
  path: string;
  name: string;
  category: 'core' | 'detection' | 'security' | 'service' | 'ui' | 'tests' | 'docs';
  content: string;
}
