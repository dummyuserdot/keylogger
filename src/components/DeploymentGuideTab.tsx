import React from 'react';
import { Terminal, Shield, Lock, FileCheck, AlertTriangle, Layers, Info } from 'lucide-react';

export const DeploymentGuideTab: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Windows 10 &amp; Windows 11 Security Architecture &amp; Hardening</span>
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
          KeySentinel employs defense-in-depth principles: user-mode low-level keyboard hook inspection,
          cryptographic configuration baselining, and Windows Service Control Manager (SCM) access restrictions.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Step 1: Virtual Environment */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <span className="w-5 h-5 rounded-full bg-cyan-600 text-white flex items-center justify-center text-[11px] font-mono">
              1
            </span>
            <span>Virtual Environment &amp; Dependency Setup</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Run PowerShell as Administrator to ensure full access to Windows ctypes and process APIs:
          </p>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 space-y-1">
            <div><span className="text-slate-500"># Create virtual environment</span></div>
            <div>python -m venv venv</div>
            <div>.\venv\Scripts\Activate.ps1</div>
            <div><span className="text-slate-500"># Install dependencies</span></div>
            <div>pip install -r requirements.txt</div>
          </div>
        </div>

        {/* Step 2: Directory ACL Hardening */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <span className="w-5 h-5 rounded-full bg-cyan-600 text-white flex items-center justify-center text-[11px] font-mono">
              2
            </span>
            <span>Windows File Access Control Lists (icacls)</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Protect configuration and audit logs so standard non-admin users cannot alter or delete them:
          </p>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 space-y-1">
            <div><span className="text-slate-500"># Restrict config &amp; logs to SYSTEM &amp; Admins</span></div>
            <div>icacls .\config /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F</div>
            <div>icacls .\logs /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F</div>
          </div>
        </div>

        {/* Step 3: Windows Service Installation */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <span className="w-5 h-5 rounded-full bg-cyan-600 text-white flex items-center justify-center text-[11px] font-mono">
              3
            </span>
            <span>Windows Service Control Manager (SCM)</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Run continuously in the background across user logoffs using native Windows Service mode:
          </p>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 space-y-1">
            <div><span className="text-slate-500"># Register KeySentinel Windows Service</span></div>
            <div>python service\windows_service.py install</div>
            <div><span className="text-slate-500"># Start service via SCM</span></div>
            <div>python service\windows_service.py start</div>
            <div><span className="text-slate-500"># Query service health</span></div>
            <div>sc query KeySentinelService</div>
          </div>
        </div>

        {/* Step 4: SDDL Permission Lockdown */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <span className="w-5 h-5 rounded-full bg-cyan-600 text-white flex items-center justify-center text-[11px] font-mono">
              4
            </span>
            <span>Service Control Lock Down (SDDL)</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Prevent unprivileged local users from issuing <code className="text-cyan-300">sc stop KeySentinelService</code>:
          </p>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 space-y-1">
            <div><span className="text-slate-500"># Apply Security Descriptor (SDDL)</span></div>
            <div className="break-all">sc sdset KeySentinelService "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)"</div>
          </div>
        </div>
      </div>

      {/* Security Limitations Callout */}
      <div className="bg-slate-900 border border-amber-800/60 rounded-xl p-5 space-y-2 text-xs text-slate-300">
        <div className="flex items-center space-x-2 text-amber-400 font-bold">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Transparent Security Boundaries &amp; Operational Reality</span>
        </div>
        <p className="leading-relaxed">
          As a matter of rigorous cybersecurity engineering: No software running in user space or as a standard Windows service
          can mathematically prevent termination by an adversary who holds root SYSTEM or kernel-mode debugging privileges.
          KeySentinel establishes tamper resistance against standard users and unauthorized actors through strict Windows ACLs,
          authenticated shutdown gates (Password: <code className="text-cyan-300 font-bold">27254</code>), and real-time cryptographic audit trails.
        </p>
      </div>
    </div>
  );
};
