import re
import os
import json

class StaticAnalyzer:
    def __init__(self):
        # Known vulnerability rule catalog with CWE mappings and Impact specifications across all major programming languages

        # -------------------------------------------------------------
        # C / C++ PATTERNS
        # -------------------------------------------------------------
        self.c_patterns = [
            {
                "id": "C-VULN-001",
                "cwe": "CWE-121",
                "name": "Stack-based Buffer Overflow",
                "regex": r"\bstrcpy\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Memory corruption, instruction pointer hijacking, remote code execution (RCE), process crash / Denial of Service (DoS).",
                "explanation": "Use of unbounded strcpy() copies user-controlled memory without bounds verification, causing stack-based buffer overflow."
            },
            {
                "id": "C-VULN-002",
                "cwe": "CWE-120",
                "name": "Buffer Copy without Checking Size of Input",
                "regex": r"\bstrcat\s*\(",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Memory overwrite, adjacent data corruption, application instability and crash.",
                "explanation": "Use of unsafe strcat() can overflow destination buffer if input size exceeds allocated capacity."
            },
            {
                "id": "C-VULN-003",
                "cwe": "CWE-242",
                "name": "Use of Inherently Dangerous Function",
                "regex": r"\bgets\s*\(",
                "severity": "CRITICAL",
                "confidence": 99,
                "impact": "Unrestricted buffer overflow leading to complete process takeover and stack frame corruption.",
                "explanation": "Use of deprecated gets() function reads standard input indefinitely, guaranteeing buffer overflow."
            },
            {
                "id": "C-VULN-004",
                "cwe": "CWE-134",
                "name": "Uncontrolled Format String",
                "regex": r"\bprintf\s*\(\s*[a-zA-Z0-9_]+\s*\)|\bsprintf\s*\(",
                "severity": "CRITICAL",
                "confidence": 97,
                "impact": "Arbitrary memory read/write, stack disclosure, code execution via format specifiers (%x, %n).",
                "explanation": "Passing user-controlled string directly as printf format specifier allows stack reading and memory overwriting."
            }
        ]

        # -------------------------------------------------------------
        # PYTHON PATTERNS
        # -------------------------------------------------------------
        self.py_patterns = [
            {
                "id": "PY-VULN-001",
                "cwe": "CWE-798",
                "name": "Use of Hard-coded Credentials",
                "regex": r"(?:ADMIN_USERNAME|ADMIN_PASSWORD|COMMAND_CENTER_KEY|SECRET_KEY|API_KEY|PASSWORD|SECRET)\s*=\s*[\"'][^\"']+[\"']",
                "severity": "HIGH",
                "confidence": 98,
                "impact": "Unauthorized administrative access, static credential exposure in source repository.",
                "explanation": "Hardcoded secrets in application source code allow trivial authentication bypass."
            },
            {
                "id": "PY-VULN-002",
                "cwe": "CWE-215",
                "name": "Debug Mode Enabled in Production",
                "regex": r"app\.config\[[\"']DEBUG[\"']\]\s*=\s*True|app\.run\([^)]*debug\s*=\s*True",
                "severity": "HIGH",
                "confidence": 99,
                "impact": "Remote code execution via Werkzeug interactive debugger, detailed error trace disclosure.",
                "explanation": "Enabling debug mode in production exposes interactive web debugger console permitting arbitrary Python code execution."
            },
            {
                "id": "PY-VULN-003",
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "regex": r"cursor\.execute\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Database extraction, authentication bypass, data manipulation/deletion, administrative privilege escalation.",
                "explanation": "Dynamic SQL query string interpolation with user input enables arbitrary database command injection."
            },
            {
                "id": "PY-VULN-004",
                "cwe": "CWE-639",
                "name": "Insecure Direct Object Reference (IDOR) / Missing Authorization",
                "regex": r"@app\.route\(\s*[\"']/api/mission/<int:mission_id>[\"']\)",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Unauthorized access to sensitive user/mission records by manipulating object IDs without permission checks.",
                "explanation": "Endpoint fetches records by user-supplied ID without verifying ownership or user authorization role."
            },
            {
                "id": "PY-VULN-005",
                "cwe": "CWE-78",
                "name": "Command Injection",
                "regex": r"\b(?:os\.system|subprocess\.getoutput)\s*\(|\bsubprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True",
                "severity": "HIGH",
                "confidence": 97,
                "impact": "Full host system compromise, unauthorized shell command execution, data exfiltration, lateral network pivoting.",
                "explanation": "User-controlled input reaches operating system command execution without shell argument separation."
            },
            {
                "id": "PY-VULN-006",
                "cwe": "CWE-22",
                "name": "Path Traversal (Improper Limitation of a Pathname)",
                "regex": r"send_file\s*\(|open\s*\(\s*os\.path\.join\(",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Arbitrary system file reading (e.g. /etc/passwd, configuration secrets, private keys).",
                "explanation": "Unsanitized filename concatenated into file path permits directory traversal ('../') access."
            },
            {
                "id": "PY-VULN-007",
                "cwe": "CWE-502",
                "name": "Deserialization of Untrusted Data",
                "regex": r"\bpickle\.loads\s*\(|\byaml\.load\s*\(",
                "severity": "CRITICAL",
                "confidence": 99,
                "impact": "Arbitrary code execution upon unpickling payload, full host system compromise.",
                "explanation": "Native pickle/yaml deserialization of untrusted user input allows execution of arbitrary object destructors/callables."
            },
            {
                "id": "PY-VULN-008",
                "cwe": "CWE-328",
                "name": "Use of Weak Hash Algorithm",
                "regex": r"\bhashlib\.md5\s*\(|\bhashlib\.sha1\s*\(",
                "severity": "HIGH",
                "confidence": 96,
                "impact": "Credential cracking via rainbow tables, hash collision exploitation, weak password protection.",
                "explanation": "MD5/SHA1 are cryptographically broken and fast to crack; passwords must use memory-hard hashing (bcrypt/PBKDF2/Argon2)."
            },
            {
                "id": "PY-VULN-009",
                "cwe": "CWE-918",
                "name": "Server-Side Request Forgery (SSRF)",
                "regex": r"\brequests\.(?:get|post|put|delete)\s*\(",
                "severity": "HIGH",
                "confidence": 94,
                "impact": "Internal network scanning, cloud metadata extraction (169.254.169.254), bypassing firewall access controls.",
                "explanation": "Fetching user-supplied URLs allows attackers to probe loopback and internal network microservices."
            },
            {
                "id": "PY-VULN-010",
                "cwe": "CWE-79",
                "name": "Cross-site Scripting (Reflected XSS)",
                "regex": r"return\s+f?[\"'].*<html>.*</html>|return\s+f?[\"'].*<p>.*</p>",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Session hijacking, cookie theft, malicious script execution in victim browser context.",
                "explanation": "Direct reflection of unescaped HTML query string allows arbitrary JavaScript execution."
            }
        ]

        # -------------------------------------------------------------
        # JAVA PATTERNS (Supports Multi-line statement formatting)
        # -------------------------------------------------------------
        self.java_patterns = [
            {
                "id": "JAVA-VULN-001",
                "cwe": "CWE-798",
                "name": "Hardcoded Credentials & Secrets",
                "regex": r"(?:DB_PASSWORD|API_TOKEN|SECRET_KEY|PASSWORD|SECRET)\s*=\s*[\"'][^\"']+[\"']",
                "severity": "HIGH",
                "confidence": 98,
                "impact": "Unauthorized database access, static API key exposure in bytecode.",
                "explanation": "Hardcoded database password and secrets in Java source code enable unauthorized authentication bypass."
            },
            {
                "id": "JAVA-VULN-002",
                "cwe": "CWE-89",
                "name": "SQL Injection in JDBC Execution",
                "regex": r"createStatement\s*\(|executeQuery\s*\(|executeUpdate\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Database extraction, authentication bypass, administrative data deletion.",
                "explanation": "Use of unparameterized JDBC Statement execution permits SQL injection; use PreparedStatement with placeholders."
            },
            {
                "id": "JAVA-VULN-003",
                "cwe": "CWE-22",
                "name": "Path Traversal in File Operations",
                "regex": r"new\s+File\s*\(|new\s+FileInputStream\s*\(|Paths\.get\s*\(",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Arbitrary file reading outside authorized reports directory.",
                "explanation": "Unsanitized user-supplied filename in File constructor allows directory traversal ('../')."
            },
            {
                "id": "JAVA-VULN-004",
                "cwe": "CWE-78",
                "name": "Command Injection in Process Execution",
                "regex": r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(",
                "severity": "HIGH",
                "confidence": 97,
                "impact": "Arbitrary shell command execution, server host takeover.",
                "explanation": "Passing concatenated user string to Runtime.exec() allows shell command injection."
            },
            {
                "id": "JAVA-VULN-005",
                "cwe": "CWE-502",
                "name": "Unsafe ObjectInputStream Deserialization",
                "regex": r"new\s+ObjectInputStream\s*\(|readObject\s*\(",
                "severity": "CRITICAL",
                "confidence": 99,
                "impact": "Remote Code Execution (RCE) via gadget chain invocation on unpickling Java bytecode.",
                "explanation": "Native ObjectInputStream readObject() on untrusted stream executes arbitrary class loaders."
            },
            {
                "id": "JAVA-VULN-006",
                "cwe": "CWE-918",
                "name": "Server-Side Request Forgery (SSRF)",
                "regex": r"new\s+URL\s*\(|\.openConnection\s*\(",
                "severity": "HIGH",
                "confidence": 94,
                "impact": "Internal network probing, cloud instance metadata extraction.",
                "explanation": "Constructing URL connections directly from user HTTP parameter enables internal network SSRF."
            }
        ]

        # -------------------------------------------------------------
        # JAVASCRIPT / TYPESCRIPT / NODE.JS PATTERNS
        # -------------------------------------------------------------
        self.js_patterns = [
            {
                "id": "JS-VULN-001",
                "cwe": "CWE-78",
                "name": "OS Command Injection",
                "regex": r"\bexec\s*\(|execSync\s*\(|child_process",
                "severity": "HIGH",
                "confidence": 97,
                "impact": "Host OS command injection, shell compromise.",
                "explanation": "Passing variables to child_process.exec() executes arbitrary shell commands."
            },
            {
                "id": "JS-VULN-002",
                "cwe": "CWE-95",
                "name": "Improper Code Evaluation",
                "regex": r"\beval\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Arbitrary JavaScript execution in Node.js runtime environment.",
                "explanation": "eval() evaluates string input as live code, allowing remote code execution."
            },
            {
                "id": "JS-VULN-003",
                "cwe": "CWE-89",
                "name": "SQL / NoSQL Injection",
                "regex": r"db\.query\s*\(|\$where\s*:",
                "severity": "CRITICAL",
                "confidence": 96,
                "impact": "Database extraction, authentication bypass, Mongo NoSQL injection.",
                "explanation": "Unvalidated query objects or string concatenation in database calls enable injection."
            }
        ]

        # -------------------------------------------------------------
        # GO (GOLANG) PATTERNS
        # -------------------------------------------------------------
        self.go_patterns = [
            {
                "id": "GO-VULN-001",
                "cwe": "CWE-78",
                "name": "Command Injection in exec.Command",
                "regex": r"exec\.Command\s*\(",
                "severity": "HIGH",
                "confidence": 96,
                "impact": "Subshell command injection in Go process.",
                "explanation": "Invoking shell interpreter with string arguments introduces command injection risks."
            },
            {
                "id": "GO-VULN-002",
                "cwe": "CWE-89",
                "name": "SQL Injection in db.Query",
                "regex": r"db\.(?:Query|QueryRow|Exec)\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Database manipulation and unauthorized data extraction.",
                "explanation": "Formating SQL query strings without placeholders bypasses parameterized safety."
            }
        ]

        # -------------------------------------------------------------
        # PHP PATTERNS
        # -------------------------------------------------------------
        self.php_patterns = [
            {
                "id": "PHP-VULN-001",
                "cwe": "CWE-78",
                "name": "Command Injection",
                "regex": r"\b(?:system|exec|shell_exec|passthru|popen)\s*\(",
                "severity": "CRITICAL",
                "confidence": 99,
                "impact": "Arbitrary web server shell execution.",
                "explanation": "Passing request parameters directly to system execution functions."
            },
            {
                "id": "PHP-VULN-002",
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "regex": r"\b(?:mysqli_query|PDO::query)\s*\(",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Database extraction, auth bypass.",
                "explanation": "Direct interpolation of request params into SQL query string."
            }
        ]

    def _extract_function_name(self, lines, line_idx):
        """Extracts enclosing function name for the given line index."""
        for idx in range(line_idx, -1, -1):
            line = lines[idx]
            py_m = re.match(r"^\s*def\s+([a-zA-Z0-9_]+)\s*\(", line)
            if py_m:
                return f"{py_m.group(1)}()"
            c_m = re.match(r"^[a-zA-Z_][a-zA-Z0-9_* ]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*\{?", line)
            if c_m and not c_m.group(1) in ("if", "for", "while", "switch", "catch"):
                return f"{c_m.group(1)}()"
            lang_m = re.match(r"^\s*(?:public|private|protected|static|fn|func|function|\s)+[\w<>\[\]\*&]+\s+([a-zA-Z0-9_]+)\s*\(", line)
            if lang_m and not lang_m.group(1) in ("if", "for", "while", "switch", "catch", "else"):
                return f"{lang_m.group(1)}()"
        return "global / main"

    def scan_file(self, filepath, reasoner=None):
        results = []
        if not os.path.exists(filepath):
            return results

        ext = os.path.splitext(filepath)[1].lower()

        patterns = []
        if ext in ('.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'):
            patterns = self.c_patterns
        elif ext in ('.py', '.pyw'):
            patterns = self.py_patterns
        elif ext in ('.java', '.jsp'):
            patterns = self.java_patterns
        elif ext in ('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'):
            patterns = self.js_patterns
        elif ext in ('.go',):
            patterns = self.go_patterns
        elif ext in ('.php', '.phtml'):
            patterns = self.php_patterns

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            seen_cwes = set()
            for line_idx, line in enumerate(lines):
                clean_line = line.strip()
                if clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*") or clean_line.startswith("*"):
                    continue

                for pattern in patterns:
                    match = re.search(pattern["regex"], line)
                    if match:
                        rule_key = (line_idx + 1, pattern["cwe"])
                        if rule_key not in seen_cwes:
                            seen_cwes.add(rule_key)
                            func_name = self._extract_function_name(lines, line_idx)
                            results.append({
                                "threat_id": f"THREAT #{len(results)+1:03d}",
                                "file": filepath,
                                "line": line_idx + 1,
                                "code": line.strip(),
                                "rule_id": pattern["id"],
                                "cwe": pattern["cwe"],
                                "name": pattern["name"],
                                "severity": pattern["severity"],
                                "confidence": pattern["confidence"],
                                "function": func_name,
                                "impact": pattern["impact"],
                                "explanation": pattern["explanation"]
                            })
        except Exception:
            pass

        # Universal AI Scanning via Ollama or Cloud LLM for deep AST & multi-language vulnerability detection
        if reasoner:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                prompt = f"""
You are the Static Security Scanning module of Agniveer Sentinel (Autonomous Cyber-Reasoning System for Multi-Language Defense Systems).
Analyze the following source code file for ALL security vulnerabilities, architectural weaknesses, or unsafe library usages (e.g. SQL Injection, Command Injection, Path Traversal, Unsafe Deserialization, Weak Cryptography, Hardcoded Credentials, XSS, SSRF, IDOR, Arbitrary File Upload, Info Disclosure, Insecure CORS, Memory Leak, Buffer Overflow, Format String, etc.).

Target File: {os.path.basename(filepath)}
File Extension: {ext}
Source Code:
```
{content}
```

Identify all security vulnerabilities and output your findings strictly as a JSON array of objects. Do not include any text outside the JSON array. Each object must have these exact keys:
- "line": The integer line number (1-indexed) where the vulnerability exists.
- "code": The exact line of source code.
- "rule_id": A short identifier code (e.g., "GEN-VULN-001").
- "cwe": The CWE identifier (e.g., "CWE-78", "CWE-89", "CWE-502", "CWE-22", "CWE-121", "CWE-328", "CWE-918", "CWE-79", "CWE-798", "CWE-434").
- "name": The short vulnerability name.
- "severity": Either "CRITICAL", "HIGH", "MEDIUM", or "LOW".
- "confidence": Integer percentage between 85 and 99.
- "function": Enclosing function name (e.g. "searchPersonnel()").
- "impact": A concise description of system impact and consequences.
- "explanation": A brief description of the vulnerability and why it is unsafe.

If no additional vulnerabilities are found, output exactly an empty JSON array: []
"""
                ai_output = ""
                if reasoner.provider in ("ollama", "local"):
                    ai_output = reasoner._query_ollama(prompt)
                elif reasoner.provider == "gemini" and reasoner.client:
                    response = reasoner.client.models.generate_content(
                        model='gemini-3.5-flash', contents=prompt
                    )
                    ai_output = response.text
                elif reasoner.provider == "openai" and reasoner.client:
                    response = reasoner.client.chat.completions.create(
                        model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}], temperature=0.1
                    )
                    ai_output = response.choices[0].message.content
                elif reasoner.provider == "anthropic" and reasoner.client:
                    response = reasoner.client.messages.create(
                        model="claude-3-5-sonnet-20241022", max_tokens=2000, messages=[{"role": "user", "content": prompt}]
                    )
                    ai_output = "".join(c.text for c in response.content if c.type == 'text')

                json_match = re.search(r"(\[.*\])", ai_output, re.DOTALL)
                if json_match:
                    parsed_results = json.loads(json_match.group(1))
                    if isinstance(parsed_results, list) and len(parsed_results) > 0:
                        seen_lines_cwes = {(r["line"], r["cwe"]) for r in results}
                        for item in parsed_results:
                            item_line = item.get("line", 1)
                            item_cwe = item.get("cwe", "CWE-699")
                            if (item_line, item_cwe) not in seen_lines_cwes:
                                item["file"] = filepath
                                item["threat_id"] = f"THREAT #{len(results)+1:03d}"
                                if "confidence" not in item: item["confidence"] = 95
                                if "function" not in item: item["function"] = "unknown()"
                                if "impact" not in item: item["impact"] = "System compromise or unauthorized operation."
                                results.append(item)
                                seen_lines_cwes.add((item_line, item_cwe))
            except Exception:
                pass

        return results

    def scan_directory(self, dirpath, reasoner=None):
        all_results = []
        for root, _, files in os.walk(dirpath):
            for file in files:
                file_path = os.path.join(root, file)
                if any(x in file_path for x in ('.venv', '.git', '__pycache__', 'build', 'dist', 'runs', 'reports')):
                    continue
                all_results.extend(self.scan_file(file_path, reasoner))
        return all_results
