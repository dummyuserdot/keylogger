# KeySentinel — Windows Keylogger Detection & Security Monitor

**KeySentinel** is a defensive Windows desktop security monitor designed to detect unauthorized keyboard-capture hooks, stealth persistence mechanisms, and process masquerading without ever recording user keystrokes. It protects its configuration and monitoring lifecycle using native Windows Access Control Lists (ACLs) and enforces an authenticated administrator shutdown workflow.

---

## Key Features

1. **Defensive Detection Engine**
   - Monitors Windows Low-Level Keyboard Hooks (`WH_KEYBOARD` = 2, `WH_KEYBOARD_LL` = 13) via `user32.dll`.
   - Identifies Raw Input listeners configured with `RIDEV_INPUTSINK` (0x00000100) capturing keystrokes in unfocused background states.
   - Flags suspicious `GetAsyncKeyState` and `GetKeyboardState` polling loops.
   - Detects executables running from volatile or hidden user folders (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`).
   - Identifies process masquerading (e.g., rogue processes named `svchost.exe` running outside `C:\Windows\System32`).
   - Anti-False-Positive Filter: Recognizes legitimate tools (e.g., Discord Overlay, Microsoft PowerToys, OBS Studio hotkeys) and distinguishes a *Suspicious Indicator* from a *Confirmed Keylogger*.

2. **Administrator Authentication & Controlled Shutdown**
   - Development Prototype Password: `27254`
   - Masked password dialog with debouncing to prevent duplicate shutdown triggers.
   - Rate-limiting lockout: 5 consecutive failed attempts lock the interface for 30 seconds.
   - Passwords and keystrokes are **strictly never recorded or logged**.
   - Modular verification architecture enabling drop-in replacement with PBKDF2/Argon2.

3. **Tamper & Termination Resistance**
   - Restricts log and configuration directories using Windows Access Control Lists (`icacls`) granting permissions solely to `Administrators` and `SYSTEM`.
   - Continuous configuration integrity verification via SHA-256 cryptographic baselines.
   - Optional Windows Service integration with Service Control Manager (SCM) and Security Descriptor Definition Language (SDDL) protection.
   - Graceful degradation with clear alerts when running in non-elevated user contexts.

4. **Security Event Audit Logging**
   - Structured JSON logs categorized by `AUTHENTICATION`, `SUSPICIOUS_PROCESS`, `PERSISTENCE_TAMPER`, `CONFIG_INTEGRITY`, and `SERVICE_CONTROL`.
   - Automatic log redaction filter to eliminate potential secrets.

---

## System Requirements & Technology Stack

- **Operating System:** Windows 10 (64-bit) or Windows 11 (64-bit) (Cross-platform compatibility fallback supported for testing)
- **Language:** Python 3.8 to 3.12+
- **GUI:** Tkinter (Standard Python Library)
- **Dependencies:** `psutil>=5.9.0`, `pywin32>=306` (Windows)

---

## Installation & Quick Start

### 1. Clone or Extract Project
```bash
git clone https://github.com/your-org/keysentinel.git
cd keysentinel
```

### 2. Create and Activate Virtual Environment
```powershell
# In PowerShell (Run as Administrator recommended for full ACL protection):
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Required Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run KeySentinel Desktop Application
```bash
# Launch Tkinter GUI Dashboard:
python main.py

# Or launch Headless Console Monitor:
python main.py --cli
```

---

## Windows Service Installation (Optional Continuous Monitoring)

To run KeySentinel continuously in the background under the Windows Service Control Manager:

```powershell
# Open an elevated PowerShell prompt (Run as Administrator):
python service\windows_service.py install

# Start the service:
python service\windows_service.py start

# Verify status:
sc query KeySentinelService

# To stop (requires Administrator privileges):
python service\windows_service.py stop
```

---

## Administrator Shutdown Workflow

1. Upon requesting shutdown via the GUI button or window close event, KeySentinel displays the **Administrator Authentication Modal**.
2. Enter the prototype administrator password:
   ```
   27254
   ```
3. KeySentinel verifies the salted SHA-256 hash in constant time.
4. Upon successful verification:
   - Audit event `APPLICATION_SHUTDOWN_AUTHORIZED` is logged.
   - Background inspection threads are stopped cleanly.
   - Open hook handles and system resources are unregistered.
   - The GUI window exits with code 0.
5. If an incorrect password is entered:
   - Audit event `ADMIN_AUTHENTICATION_FAILURE` is recorded.
   - An error dialog appears showing remaining attempts.
   - Monitoring continues running uninterrupted.

---

## Running the Automated Test Suite

KeySentinel includes comprehensive unit and integration tests covering all 10 required security scenarios:

```bash
# Execute test runner:
python tests/test_runner.py

# Or using unittest discover:
python -m unittest discover tests
```

### Test Coverage Scenarios
| Scenario ID | Test Description | Status |
| :--- | :--- | :--- |
| **01** | Correct administrator password `27254` authorizes graceful shutdown | **PASSED** |
| **02** | Incorrect password does not stop monitoring | **PASSED** |
| **03** | Cancelling authentication dialog leaves monitoring active | **PASSED** |
| **04** | Monitoring starts and stops cleanly without lingering threads | **PASSED** |
| **05** | Suspicious process indicators generate alerts with evidence | **PASSED** |
| **06** | Unauthorized configuration changes detected via integrity hash | **PASSED** |
| **07** | Insufficient Windows privileges produce clear warnings | **PASSED** |
| **08** | Engine handles inaccessible processes and API failures gracefully | **PASSED** |
| **09** | GUI and background workers operate asynchronously without freezing | **PASSED** |
| **10** | Service-control permissions enforce administrative elevation | **PASSED** |

---

## Security Model & Transparent Limitations

KeySentinel follows industry-standard defensive transparency:

- **Anti-False-Positive Discipline:** Many legitimate utilities (e.g., Discord Overlay, Zoom, PowerToys, screen recorders) use low-level keyboard hooks. KeySentinel treats hooks as *suspicious indicators* and requires correlated clandestine traits (such as temp folder execution or masquerading) before elevating to a *confirmed keylogger* verdict.
- **Privilege Boundaries:** No user-mode or service process can prevent termination by a user with higher or equivalent local `NT AUTHORITY\SYSTEM` or debug privileges (`SeDebugPrivilege`). KeySentinel uses Windows ACLs and SCM security descriptors to prevent unauthorized standard users from tampering with files or stopping the service.
- **Privacy Assurance:** KeySentinel inspects metadata, hook tables, and module references. It **never captures keystroke data, intercepts keystroke buffers, or records user passwords**.
