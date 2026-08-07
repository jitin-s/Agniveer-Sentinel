import re
import os
import json

class StaticAnalyzer:
    def __init__(self):
        # Vulnerable pattern signatures for C code
        self.c_patterns = [
            {
                "id": "C-VULN-001",
                "name": "Unsafe String Copy",
                "regex": r"\bstrcpy\s*\(\s*[^,]+,\s*([^)]+)\)",
                "severity": "CRITICAL",
                "explanation": "Use of unsafe 'strcpy()' function detected. It does not check bounds and can lead to stack-based buffer overflows."
            },
            {
                "id": "C-VULN-002",
                "name": "Unsafe Buffer Concat",
                "regex": r"\bstrcat\s*\(\s*[^,]+,\s*([^)]+)\)",
                "severity": "HIGH",
                "explanation": "Use of unsafe 'strcat()' detected. It can overflow buffers if the destination size is too small."
            },
            {
                "id": "C-VULN-003",
                "name": "Unsafe Input Read",
                "regex": r"\bgets\s*\(\s*[^)]+\)",
                "severity": "CRITICAL",
                "explanation": "Use of 'gets()' detected. This function is deprecated and fundamentally vulnerable to buffer overflow because it reads stdin indefinitely."
            }
        ]

        # Vulnerable pattern signatures for Python code
        self.py_patterns = [
            {
                "id": "PY-VULN-001",
                "name": "Shell Execution via System Call",
                "regex": r"\bos\.system\s*\(\s*([^)]+)\)",
                "severity": "CRITICAL",
                "explanation": "Use of 'os.system()' with concatenated inputs allows arbitrary shell command execution."
            },
            {
                "id": "PY-VULN-002",
                "name": "Insecure Subprocess Execution",
                "regex": r"\bsubprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True[^)]*\)",
                "severity": "HIGH",
                "explanation": "Subprocess execution with shell=True enabled. This can lead to shell command injection vulnerabilities."
            },
            {
                "id": "PY-VULN-003",
                "name": "Dynamic Code Evaluation",
                "regex": r"\b(?:eval|exec)\s*\(\s*([^)]+)\)",
                "severity": "HIGH",
                "explanation": "Use of dynamic code evaluator 'eval()' or 'exec()' on untrusted inputs allows arbitrary code execution."
            }
        ]

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
- "name": The short vulnerability name.
- "severity": Either "CRITICAL", "HIGH", "MEDIUM", or "LOW".
- "explanation": A brief description of the vulnerability and why it is unsafe.

If no vulnerabilities are found, output exactly an empty JSON array: []
"""
                ai_output = ""
                if reasoner.provider == "gemini":
                    # Google Gemini Call
                    response = reasoner.client.models.generate_content(
                        model='gemini-3.5-flash',
                        contents=prompt
                    )
                    ai_output = response.text
                elif reasoner.provider == "openai":
                    # OpenAI Call
                    response = reasoner.client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1
                    )
                    ai_output = response.choices[0].message.content
                elif reasoner.provider == "anthropic":
                    # Anthropic Call
                    response = reasoner.client.messages.create(
                        model="claude-3-5-sonnet-20241022",
                        max_tokens=2000,
                        temperature=0.1,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    response_text = ""
                    for content_block in response.content:
                        if content_block.type == 'text':
                            response_text += content_block.text
                    ai_output = response_text

                # Extract JSON block
                json_match = re.search(r"(\[.*\])", ai_output, re.DOTALL)
                if json_match:
                    parsed_results = json.loads(json_match.group(1))
                    for item in parsed_results:
                        item["file"] = filepath
                        results.append(item)
                    return results
            except Exception as e:
                # If AI scanning fails, fallback to local regex analysis
                pass

        # Local regex scanning fallback for C/Python
        patterns = []
        if ext in ('.c', '.cpp', '.h'):
            patterns = self.c_patterns
        elif ext == '.py':
            patterns = self.py_patterns
        else:
            return results  # Unsupported extension in offline mode

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
                        results.append({
                            "file": filepath,
                            "line": line_idx + 1,
                            "code": line.strip(),
                            "rule_id": pattern["id"],
                            "name": pattern["name"],
                            "severity": pattern["severity"],
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
                if any(x in file_path for x in ('.venv', '.git', '__pycache__', 'build', 'dist')):
                    continue
                all_results.extend(self.scan_file(file_path, reasoner))
        return all_results
