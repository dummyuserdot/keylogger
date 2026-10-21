import React, { useState, useEffect } from 'react';
import { Lock, Eye, EyeOff, AlertTriangle, CheckCircle, ShieldAlert, X } from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthorizedShutdown: () => void;
  onRecordFailedAttempt: (attemptCount: number) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthorizedShutdown,
  onRecordFailedAttempt,
}) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [failedCount, setFailedCount] = useState(0);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);

  // Lockout countdown timer
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (lockoutSeconds > 0) {
      interval = setInterval(() => {
        setLockoutSeconds((prev) => Math.max(0, prev - 1));
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [lockoutSeconds]);

  if (!isOpen) return null;

  const handleVerify = () => {
    // Prevent repeated clicks or execution while locked out
    if (isVerifying || lockoutSeconds > 0) return;

    if (!password) {
      setErrorMessage('Password field cannot be empty.');
      return;
    }

    setIsVerifying(true);
    setErrorMessage('');
    setSuccessMessage('');

    // Simulate verification delay (debounced)
    setTimeout(() => {
      // Prototype password verification: '27254'
      if (password === '27254') {
        setSuccessMessage('Administrator verified. Initiating graceful shutdown...');
        setFailedCount(0);
        setTimeout(() => {
          setIsVerifying(false);
          onAuthorizedShutdown();
        }, 1200);
      } else {
        const nextFailed = failedCount + 1;
        setFailedCount(nextFailed);
        onRecordFailedAttempt(nextFailed);
        setPassword('');
        setIsVerifying(false);

        if (nextFailed >= 5) {
          setLockoutSeconds(30);
          setErrorMessage('Maximum failed attempts reached. Terminal locked for 30 seconds.');
        } else {
          const remaining = 5 - nextFailed;
          setErrorMessage(`Incorrect administrator password. ${remaining} attempt(s) remaining.`);
        }
      }
    }, 450);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleVerify();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden">
        {/* Header Banner */}
        <div className="bg-slate-800/90 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Administrator Authentication
              </h3>
              <p className="text-xs text-slate-400">KeySentinel Protected Shutdown Gate</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-700/50 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          <div className="rounded-lg bg-slate-800/50 border border-slate-700 p-3 flex items-start space-x-3 text-xs text-slate-300">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p>
              Terminating KeySentinel requires authorized administrator credentials.
              Background monitoring and low-level hook surveillance remain actively defended.
            </p>
          </div>

          {/* Prototype Hint Callout */}
          <div className="bg-cyan-950/40 border border-cyan-800/50 rounded-lg p-3 text-xs text-cyan-300 flex items-center justify-between">
            <span>Configured Prototype Admin Credential:</span>
            <code className="bg-cyan-900/60 font-mono font-bold px-2 py-0.5 rounded text-cyan-200">
              27254
            </code>
          </div>

          {/* Password Input */}
          <div className="space-y-1.5">
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Enter Administrator Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isVerifying || lockoutSeconds > 0}
                placeholder="•••••"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 disabled:opacity-50"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Error Message */}
          {errorMessage && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-800/60 text-xs text-red-300 flex items-start space-x-2 animate-shake">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Success Message */}
          {successMessage && (
            <div className="p-3 rounded-lg bg-emerald-950/50 border border-emerald-800/60 text-xs text-emerald-300 flex items-start space-x-2">
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Lockout Warning */}
          {lockoutSeconds > 0 && (
            <div className="text-center py-2 text-xs font-mono font-bold text-amber-400 animate-pulse">
              Authentication Throttled: Retrying in {lockoutSeconds}s
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="bg-slate-950/80 px-6 py-4 border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={onClose}
            disabled={isVerifying}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            Cancel (Keep Active)
          </button>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleVerify}
              disabled={isVerifying || lockoutSeconds > 0}
              className="px-4 py-2 rounded-lg text-xs font-bold text-white bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed shadow-md hover:shadow-red-600/30 transition-all flex items-center space-x-1.5"
            >
              {isVerifying ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Verifying...</span>
                </>
              ) : (
                <span>Verify &amp; Shutdown</span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
