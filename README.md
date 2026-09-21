## Agniveer Sentinel (AI Kavach)
#### Autonomous AI Cyber-Reasoning & Remediation System (CRS)

> **"An autonomous AI cyber-reasoning and remediation system that detects vulnerabilities using static and dynamic analysis, reasons about their root cause, generates security patches, and autonomously verifies those patches through adversarial and regression testing."**

---

## System Architecture

Agniveer Sentinel implements a complete, closed-loop cyber-reasoning pipeline built for mission-critical and defense-grade environments:

```
[Target Source Code]
        │
        ▼
[CLI Orchestrator]
        │
        ▼
[Stage 1: Static AST & Vulnerability Scan]
        │
        ▼
[Stage 2: Dynamic Fuzzing & Exploit Verification Sandbox]
        │
        ▼
[Stage 3: AI Reasoning Engine (CWE, Root-Cause, Attack Surface, Strategy)]
        │
        ▼
[Patch Generator (Production-Safe & Hardened Remediation)]
        │
        ▼
[Stage 4: 5-Point Security & Regression Verification Suite]
   ├── 1. Original exploit reproduced before patch
   ├── 2. Exploit blocked & neutralized after patch
   ├── 3. Valid functional inputs passed
   ├── 4. Regression test suite passed
   └── 5. Post-patch AST re-scan clean (0 new issues)
        │
        ├── [FAIL] ──► [Patch-Failure Retry Loop (Max 3 Attempts)]
        │
        ▼ [PASS]
[Evidence Package Preservation (runs/ directory)]
        │
        ▼
[Final Autonomous Verdict]
```

---

## 💻 CLI Commands Reference

Agniveer Sentinel provides 6 modular subcommands:

| Command | Purpose |
| :--- | :--- |
| `python agniveer_sentinel.py scan --target <target>` | Find vulnerabilities without modifying the target file. |
| `python agniveer_sentinel.py run --target <target>` | Run the complete autonomous self-healing pipeline. |
| `python agniveer_sentinel.py verify --target <target>` | Verify whether a vulnerability is exploitable or whether a patch is effective. |
| `python agniveer_sentinel.py patch --target <target>` | Generate and apply an AI remediation patch directly. |
| `python agniveer_sentinel.py report --run <RUN_ID>` | Generate and display the final evidence report from a previous run. |
| `python agniveer_sentinel.py rollback --run <RUN_ID>` | Restore the original source file state from the preserved evidence package. |

---

## 🔒 Security Notice & API Key Safety
*   **DO NOT** push your local `.env` file containing private API keys to GitHub.
*   A `.gitignore` file is pre-configured in this repository to prevent tracking of `.env` files and `.venv` folders.

---

## 🚀 Setup & Installation Guide

### 1. Clone the GitHub Repository
```bash
git clone https://github.com/jitin-s/Agniveer-Sentinel.git
cd Agniveer-Sentinel
```

### 2. Create and Activate Virtual Environment
```bash
# Create environment
python -m venv .venv

# Activate on Git Bash (Windows) / macOS / Linux:
source .venv/Scripts/activate   # (or source .venv/bin/activate on Linux/Mac)

# Activate on Command Prompt (cmd.exe):
.venv\Scripts\activate.bat

# Activate on PowerShell:
.venv/Scripts/Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🔑 How to Generate a Gemini API Key

To enable real-time LLM reasoning and patch synthesis:
1.  Navigate to **[Google AI Studio](https://aistudio.google.com/)**.
2.  Sign in with your Google account.
3.  Click the blue **"Get API key"** button in the top-left corner.
4.  Select **"Create API key"**.
5.  Copy your generated key (starts with `AIzaSy...`).
6.  Paste it into your local `.env` file:

```env
# Active LLM Provider: Choose from 'gemini', 'openai', 'anthropic', or 'local'
ACTIVE_PROVIDER=gemini

# Google Gemini API Key
GEMINI_API_KEY=your_copied_api_key_here

# OpenAI API Key (ChatGPT)
OPENAI_API_KEY=sk-proj-...

# Anthropic API Key (Claude)
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 🛡️ Sample Vulnerability Targets

Sample targets demonstrating distinct security challenges are included in `test_targets/`:
1.  **`test_targets/sensor_sync.py`**: Shell Command Injection (`CWE-78`).
2.  **`test_targets/tactical_comms.c`**: Stack-based Buffer Overflow (`CWE-121`).

---

## 🧪 Usage Examples

### 1. Run the Complete Autonomous Pipeline
```bash
python agniveer_sentinel.py run --target test_targets/sensor_sync.py
```

### 2. Scan a File or Directory for Weaknesses
```bash
python agniveer_sentinel.py scan --target test_targets/
```

### 3. Verify Exploitability in Sandbox
```bash
python agniveer_sentinel.py verify --target test_targets/sensor_sync.py
```

### 4. Review Run Evidence Report
```bash
python agniveer_sentinel.py report --run latest
```

### 5. Rollback Target to Pre-Patch State
```bash
python agniveer_sentinel.py rollback --run latest
```

---

## 📦 Reproducible Evidence Packages (`runs/`)

Every autonomous execution creates a timestamped evidence directory preserving machine-readable JSON reports, unified diffs, and source snapshots:

```
runs/
└── RUN_2026-08-08_213819_sensor_sync/
    ├── original.py             # Original vulnerable code snapshot
    ├── patched.py              # Remediated code snapshot
    ├── patch.diff              # Unified diff patch
    ├── findings.json           # Detected CWE metadata & location
    ├── reasoning.json          # Root-cause analysis & patch strategy
    ├── fuzz_results.json       # Dynamic exploit payloads and crash telemetry
    ├── regression_results.json # 5-point verification test status
    └── final_report.json       # Consolidated machine-readable evidence
```

---

## ⚖️ Disclaimer
Agniveer Sentinel is developed for authorized security evaluations, educational purposes, and defensive cyber-research. Always ensure you have authorization before analyzing and patching target codebases.

---

## 📄 License
This project is licensed under the **[MIT License](LICENSE)**.
