# Agniveer-Sentinel (AI Kavach)
### Autonomous Cyber-Reasoning System (CRS) for Automated Security Analysis and Code Repair

Agniveer-Sentinel is an autonomous, self-healing Cyber-Reasoning System (CRS) designed to defend software applications. It provides an automated security loop (AI Kavach / Shield) that scans codebases for vulnerabilities, verifies findings dynamically using sandboxed fuzzing to eliminate false positives, generates secure patches using state-of-the-art LLMs, and verifies the repairs through an automated regression test harness.

Agniveer-Sentinel can scan, verify, and remediate vulnerabilities (such as buffer overflows, command injections, dynamic code evaluation, and logic exploits) across C and Python applications, with an architecture designed to support new languages and vulnerability classes.

---

## 🔒 Security Notice: Keep API Keys Safe
*   **DO NOT** push your local `.env` file containing private API keys to GitHub.
*   A `.gitignore` file is pre-configured in this repository to prevent tracking of `.env` files and `.venv` folders.

---

## 🚀 Setup & Installation Guide

Follow these steps to set up and run the Agniveer-Sentinel CRS locally on your machine.

### 1. Clone the GitHub Repository
Open your terminal and run the following command to clone the codebase:
```bash
git clone https://github.com/jitin-s/Agniveer-Sentinel.git
cd Agniveer-Sentinel
```

### 2. Create a Virtual Environment
Initialize a Python virtual environment to manage dependencies locally:
```bash
python -m venv .venv
```

### 3. Activate the Virtual Environment
Activate the environment based on your current terminal/shell:

*   **Git Bash (Windows):**
    ```bash
    source .venv/Scripts/activate
    ```
*   **PowerShell (Windows):**
    ```powershell
    .venv/Scripts/Activate.ps1
    ```
*   **Command Prompt (cmd.exe / Windows):**
    ```cmd
    .venv\Scripts\activate.bat
    ```
*   **Linux / macOS (Terminal):**
    ```bash
    source .venv/bin/activate
    ```

Once activated, your command line prompt should display `(.venv)` at the beginning.

### 4. Install Project Dependencies
Install the required libraries (including terminal layout and LLM client SDKs):
```bash
pip install -r requirements.txt
```

---

## 🔑 Step 4: Configure API Keys

1.  Copy the environment template file to create your local `.env` file:
    ```bash
    cp .env.template .env
    ```
2.  Open the newly created **`.env`** file in your text editor.
3.  Add your API keys and select your active model provider:

```env
# Active LLM Provider: Choose from 'gemini', 'openai', 'anthropic', or 'local'
ACTIVE_PROVIDER=gemini

# Google Gemini API Key
GEMINI_API_KEY=AIzaSy...

# OpenAI API Key (ChatGPT)
OPENAI_API_KEY=sk-proj-...

# Anthropic API Key (Claude)
ANTHROPIC_API_KEY=sk-ant-...
```

---

## 🛡️ Setting Up Vulnerability Targets

Agniveer-Sentinel scans and tests code targets dynamically. You can place your test subjects in any directory. The repository comes pre-loaded with sample vulnerability files under the **`test_targets/`** directory:

1.  **`test_targets/tactical_comms.c`**: A C program demonstrating a stack buffer overflow.
2.  **`test_targets/sensor_sync.py`**: A Python script demonstrating shell command injection.

You can add your own custom files to `test_targets/` or create your own custom directory containing your software target files.

---

## 💻 Running Agniveer Sentinel (Shell-Specific Commands)

Make sure your virtual environment is active (`(.venv)` should be visible in your prompt) before executing the commands.

### 1. Run the Full Self-Healing Pipeline (Scan ➔ Fuzz ➔ Patch ➔ Verify)

*   **On Git Bash (Windows) & Linux / macOS:**
    *   **Python target:**
        ```bash
        python agniveer_sentinel.py run --target test_targets/sensor_sync.py
        ```
    *   **C target:**
        ```bash
        python agniveer_sentinel.py run --target test_targets/tactical_comms.c
        ```

*   **On Command Prompt (cmd.exe - Windows):**
    *   **Python target:**
        ```cmd
        python agniveer_sentinel.py run --target test_targets\sensor_sync.py
        ```
    *   **C target:**
        ```cmd
        python agniveer_sentinel.py run --target test_targets\tactical_comms.c
        ```

*   **On PowerShell (Windows):**
    *   **Python target:**
        ```powershell
        python .\agniveer_sentinel.py run --target .\test_targets\sensor_sync.py
        ```
    *   **C target:**
        ```powershell
        python .\agniveer_sentinel.py run --target .\test_targets\tactical_comms.c
        ```

---

### 2. Run Modules Individually

*   **On Git Bash & Linux / macOS:**
    *   **Static Scanner only:**
        ```bash
        python agniveer_sentinel.py scan --target test_targets/
        ```
    *   **Sandbox Fuzzer only:**
        ```bash
        python agniveer_sentinel.py fuzz --target test_targets/tactical_comms.c
        ```

*   **On Command Prompt (cmd.exe):**
    *   **Static Scanner only:**
        ```cmd
        python agniveer_sentinel.py scan --target test_targets\
        ```
    *   **Sandbox Fuzzer only:**
        ```cmd
        python agniveer_sentinel.py fuzz --target test_targets\tactical_comms.c
        ```

*   **On PowerShell:**
    *   **Static Scanner only:**
        ```powershell
        python .\agniveer_sentinel.py scan --target .\test_targets\
        ```
    *   **Sandbox Fuzzer only:**
        ```powershell
        python .\agniveer_sentinel.py fuzz --target .\test_targets\tactical_comms.c
        ```

---

## 🧠 Supported AI Models (Multi-Provider Support)
Agniveer-Sentinel dynamically routes code repair prompts to the client configured in `ACTIVE_PROVIDER` in your `.env`:
*   **`gemini`** (Default): Uses Google `gemini-3.5-flash` model.
*   **`openai`**: Uses OpenAI `gpt-4o-mini` model.
*   **`anthropic`**: Uses Anthropic `claude-3-5-sonnet-20241022` model.
*   **`local`**: Local mode using rule-based patch fallbacks (ideal for air-gapped sandboxes).
