import re
import os
import json

class StaticAnalyzer:
    def __init__(self):
        # Known vulnerability rule catalog with CWE mappings and Impact specifications
        self.c_patterns = [
            {
                "id": "C-VULN-001",
                "cwe": "CWE-121",
                "name": "Stack-based Buffer Overflow",
                "regex": r"\bstrcpy\s*\(\s*[^,]+,\s*([^)]+)\)",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Memory corruption, instruction pointer hijacking, remote code execution (RCE), process crash / Denial of Service (DoS).",
                "explanation": "Use of unbounded strcpy() copies user-controlled memory without bounds verification, causing stack-based buffer overflow."
            },
            {
                "id": "C-VULN-002",
                "cwe": "CWE-120",
                "name": "Buffer Copy without Checking Size of Input",
                "regex": r"\bstrcat\s*\(\s*[^,]+,\s*([^)]+)\)",
                "severity": "HIGH",
                "confidence": 95,
                "impact": "Memory overwrite, adjacent data corruption, application instability and crash.",
                "explanation": "Use of unsafe strcat() can overflow destination buffer if input size exceeds allocated capacity."
            },
            {
                "id": "C-VULN-003",
                "cwe": "CWE-242",
                "name": "Use of Inherently Dangerous Function",
                "regex": r"\bgets\s*\(\s*[^)]+\)",
                "severity": "CRITICAL",
                "confidence": 99,
                "impact": "Unrestricted buffer overflow leading to complete process takeover and stack frame corruption.",
                "explanation": "Use of deprecated gets() function reads standard input indefinitely, guaranteeing buffer overflow."
            }
        ]

        self.py_patterns = [
            {
                "id": "PY-VULN-001",
                "cwe": "CWE-78",
                "name": "Command Injection",
                "regex": r"\bos\.system\s*\(\s*([^)]+)\)",
                "severity": "HIGH",
                "confidence": 97,
                "impact": "Full host system compromise, unauthorized shell command execution, data exfiltration, lateral network pivoting.",
                "explanation": "User-controlled input reaches operating system command execution without shell argument separation."
            },
            {
                "id": "PY-VULN-002",
                "cwe": "CWE-78",
                "name": "Insecure Subprocess Execution",
                "regex": r"\bsubprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True[^)]*\)",
                "severity": "HIGH",
                "confidence": 96,
                "impact": "Arbitrary command execution under process user privileges, potential privilege escalation.",
                "explanation": "Subprocess invocation with shell=True interprets metacharacters, enabling arbitrary shell execution."
            },
            {
                "id": "PY-VULN-003",
                "cwe": "CWE-94",
                "name": "Improper Control of Generation of Code (Code Injection)",
                "regex": r"\b(?:eval|exec)\s*\(\s*([^)]+)\)",
                "severity": "CRITICAL",
                "confidence": 98,
                "impact": "Arbitrary in-process Python bytecode execution, secret extraction, backdoor installation.",
                "explanation": "Dynamic code evaluator on unvalidated input allows arbitrary Python code execution."
            }
        ]

    def _extract_function_name(self, lines, line_idx):
        """Extracts enclosing function name for the given line index."""
        for idx in range(line_idx, -1, -1):
            line = lines[idx]
            # Python def
            py_m = re.match(r"^\s*def\s+([a-zA-Z0-9_]+)\s*\(", line)
            if py_m:
                return f"{py_m.group(1)}()"
            # C function definition
            c_m = re.match(r"^[a-zA-Z_][a-zA-Z0-9_* ]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*\{?", line)
            if c_m and not c_m.group(1) in ("if", "for", "while", "switch"):
                return f"{c_m.group(1)}()"
        return "global / main"

    def scan_file(self, filepath, reasoner=None):
        results = []
        if not os.path.exists(filepath):
            return results

        ext = os.path.splitext(filepath)[1].lower()
        
        # If active LLM connection is available, perform advanced language-agnostic AI scanning
        if reasoner and reasoner.client:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                prompt = f"""
You are the Static Security Scanning module of Agniveer Sentinel.
Analyze the following source code file for security vulnerabilities, weaknesses, or unsafe library usages (e.g. SQL Injection, Command Injection, Path Traversal, Weak Cryptography, XSS, SSRF, Memory Corruptions, etc.).

Target File: {os.path.basename(filepath)}
File Extension: {ext}
Source Code:
```
{content}
```

Identify all vulnerabilities and output your findings strictly as a JSON array of objects. Do not include any explanation outside the JSON block. Each object must have these exact keys:
- "line": The integer line number (1-indexed) where the issue is found.
- "code": The exact line of source code.
- "rule_id": A short identifier code (e.g., "GEN-VULN-001").
- "cwe": The CWE identifier (e.g., "CWE-78", "CWE-121", "CWE-89").
- "name": The short vulnerability name.
- "severity": Either "CRITICAL", "HIGH", "MEDIUM", or "LOW".
- "confidence": Integer percentage between 80 and 99 (e.g. 97).
- "function": Enclosing function name (e.g. "ping_sensor()").
- "impact": A concise description of what this vulnerability affects (e.g. Host Compromise, Data Theft, Denial of Service, Remote Code Execution).
- "explanation": A brief description of the vulnerability and why it is unsafe.

If no vulnerabilities are found, output exactly an empty JSON array: []
"""
                ai_output = ""
                if reasoner.provider == "gemini":
                    response = reasoner.client.models.generate_content(
                        model='gemini-3.5-flash',
                        contents=prompt
                    )
                    ai_output = response.text
                elif reasoner.provider == "openai":
                    response = reasoner.client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1
                    )
                    ai_output = response.choices[0].message.content
                elif reasoner.provider == "anthropic":
                    response = reasoner.client.messages.create(
                        model="claude-3-5-sonnet-20241022",
                        max_tokens=2000,
                        temperature=0.1,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    response_text = "".join(c.text for c in response.content if c.type == 'text')
                    ai_output = response_text

                # Extract JSON block
                json_match = re.search(r"(\[.*\])", ai_output, re.DOTALL)
                if json_match:
                    parsed_results = json.loads(json_match.group(1))
                    for idx, item in enumerate(parsed_results):
                        item["file"] = filepath
                        item["threat_id"] = f"THREAT #{idx+1:03d}"
                        if "cwe" not in item:
                            item["cwe"] = "CWE-699"
                        if "confidence" not in item:
                            item["confidence"] = 95
                        if "function" not in item:
                            item["function"] = "unknown()"
                        if "impact" not in item:
                            item["impact"] = "System compromise or unauthorized operation."
                        results.append(item)
                    return results
            except Exception:
                pass

        # Local regex scanning fallback
        patterns = []
        if ext in ('.c', '.cpp', '.h'):
            patterns = self.c_patterns
        elif ext == '.py':
            patterns = self.py_patterns
        else:
            return results

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines):
                clean_line = line.strip()
                if clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
                    continue

                for pattern in patterns:
                    match = re.search(pattern["regex"], line)
                    if match:
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
