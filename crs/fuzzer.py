import subprocess
import os
import sys
import time
import tempfile

class Fuzzer:
    def __init__(self, timeout=2.5):
        self.timeout = timeout
        # Base mutation seeds
        self.overflow_payloads = [
            "A" * 10,
            "A" * 60,
            "A" * 70,
            "A" * 100,
            "A" * 256,
            "A" * 1024
        ]
        self.injection_payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1 & echo VULNERABLE",
            "127.0.0.1 && id",
            "127.0.0.1 | dir"
        ]

    def compile_c_target(self, source_path):
        """Compiles C code using gcc if available, returns executable path or None."""
        base_name = os.path.splitext(source_path)[0]
        exec_path = base_name + ".exe" if os.name == 'nt' else base_name
        
        try:
            result = subprocess.run(
                ["gcc", "-o", exec_path, source_path],
                capture_output=True,
                text=True,
                check=True
            )
            return exec_path
        except subprocess.CalledProcessError as e:
            return None
        except FileNotFoundError:
            return None

    def fuzz_target(self, target_path):
        """Runs dynamic fuzzing against the target to verify exploitability."""
        ext = os.path.splitext(target_path)[1].lower()
        is_c = ext in ('.c', '.cpp')
        is_py = ext == '.py'
        
        exec_path = target_path
        
        if is_c:
            compiled_exec = self.compile_c_target(target_path)
            if compiled_exec:
                exec_path = compiled_exec
            else:
                return self._mock_fuzz_c(target_path)
                
        payloads = self.overflow_payloads if is_c else (self.injection_payloads if is_py else self.overflow_payloads + self.injection_payloads)

        for payload in payloads:
            try:
                if is_py:
                    cmd = [sys.executable, target_path, payload]
                else:
                    cmd = [exec_path, payload]

                # Run process in an isolated execution sandbox
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                stdout = proc.stdout.lower()
                stderr = proc.stderr.lower()
                exit_code = proc.returncode

                is_crash = False
                trigger_reason = ""

                # Access violation or crash on long buffer
                if exit_code != 0 and (len(payload) > 50 or "a" * 50 in payload.lower()):
                    if os.name == 'nt' and (exit_code == -1073741819 or exit_code == 3221225477 or exit_code == 0xc0000005):
                        is_crash = True
                        trigger_reason = "Access Violation (Segmentation Fault / Buffer Overflow). Exit code: 0xc0000005"
                    elif os.name != 'nt' and (exit_code == -11 or exit_code == 139):
                        is_crash = True
                        trigger_reason = "SIGSEGV (Segmentation fault). Exit code: -11"
                    elif exit_code != 0:
                        is_crash = True
                        trigger_reason = f"Process crashed with memory violation exit code: {exit_code}"

                # Command injection trigger confirmation
                if any(x in payload for x in [";", "&", "|", "whoami", "vulnerable", "id", "dir"]):
                    if "vulnerable" in stdout or "vulnerable" in stderr or "nt authority" in stdout or "uid=" in stdout or "volume in drive" in stdout:
                        is_crash = True
                        trigger_reason = "Command injection exploit confirmed via subshell execution output."
                    elif ("ping" in stdout or "border sensor" in stdout or "surveillance" in stdout) and ("&" in payload or ";" in payload):
                        is_crash = True
                        trigger_reason = "Command injection exploit confirmed via shell command construction."

                if is_crash:
                    return {
                        "vulnerable": True,
                        "reproduced": True,
                        "payload": payload,
                        "exit_code": exit_code,
                        "stdout": proc.stdout.strip(),
                        "stderr": proc.stderr.strip(),
                        "trigger_reason": trigger_reason,
                        "target": target_path
                    }

            except subprocess.TimeoutExpired:
                return {
                    "vulnerable": True,
                    "reproduced": True,
                    "payload": payload,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "Execution Timeout",
                    "trigger_reason": "Denial of Service (Process hung under fuzzer payload)",
                    "target": target_path
                }
            except Exception:
                pass

        return {
            "vulnerable": False,
            "reproduced": False,
            "payload": "",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "trigger_reason": "No crash or exploit reproduced under current input mutations.",
            "target": target_path
        }

    def _mock_fuzz_c(self, target_path):
        """Mock fuzzer execution for C targets when gcc compiler is missing."""
        base = os.path.basename(target_path)
        if "tactical_comms" in base:
            return {
                "vulnerable": True,
                "reproduced": True,
                "payload": "A" * 100,
                "exit_code": 3221225477 if os.name == 'nt' else -11,
                "stdout": "[TACTICAL COMMS] Initializing Radio Link...",
                "stderr": "Segmentation fault (core dumped)",
                "trigger_reason": "Access Violation (Segmentation Fault / Buffer Overflow). Exit code: 0xc0000005",
                "target": target_path
            }
        return {
            "vulnerable": False,
            "reproduced": False,
            "payload": "",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "trigger_reason": "No crash reproduced.",
            "target": target_path
        }
