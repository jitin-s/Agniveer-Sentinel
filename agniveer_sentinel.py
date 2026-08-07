#!/usr/bin/env python
import os
import sys
import argparse
import time
from crs.static_analyzer import StaticAnalyzer
from crs.fuzzer import Fuzzer
from crs.reasoner import Reasoner
from crs.test_harness import TestHarness

# Attempt to load rich console formatting. If not present, use standard prints.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.live import Live
    from rich.syntax import Syntax
    from rich.align import Align
    from rich.text import Text
    from rich.columns import Columns
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

class SentinelCLI:
    def __init__(self):
        self.analyzer = StaticAnalyzer()
        self.fuzzer = Fuzzer()
        self.reasoner = Reasoner()
        self.harness = TestHarness()
        self.console = Console() if HAS_RICH else None

    def print_banner(self):
        banner_text = """
    _    ____ _   _ _____     _______ _____  ____  
   / \  / ___| \ | |_ _\ \   / / ____| ____|  _ \ 
  / _ \| |  _|  \| || | \ \ / /|  _| |  _| | |_) |
 / ___ \ |_| | |\  || |  \ V / | |___| |___|  _ < 
/_/   \_\____|_| \_|___|  \_/  |_____|_____|_| \_\\
                 
    SENTINEL : AUTONOMOUS CYBER-REASONING SYSTEM
Youthful Agility. Relentless Vigilance. Ultimate AI Defense.
        """
        if HAS_RICH:
            self.console.print(Panel(Align.center(Text(banner_text, style="bold cyan")), border_style="cyan", title="[AI KAVACH CORE]"))
        else:
            print("+" + "-"*77 + "+")
            print(banner_text)
            print("+" + "-"*77 + "+")

    def run_static_scan(self, target_path):
        self.print_banner()
        if HAS_RICH:
            self.console.print(f"[bold yellow][i] Running Syntactic Static Scan on: {target_path}[/bold yellow]\n")
        else:
            print(f"[i] Running Syntactic Static Scan on: {target_path}\n")

        results = self.analyzer.scan_file(target_path, self.reasoner) if os.path.isfile(target_path) else self.analyzer.scan_directory(target_path, self.reasoner)

        if not results:
            if HAS_RICH:
                self.console.print("[bold green][OK] No critical syntactic vulnerabilities identified.[/bold green]")
            else:
                print("[OK] No critical syntactic vulnerabilities identified.")
            return

        if HAS_RICH:
            table = Table(title="Security Weaknesses Flagged", border_style="cyan")
            table.add_column("Rule ID", style="bold red")
            table.add_column("File Name", style="white")
            table.add_column("Line", style="yellow")
            table.add_column("Vulnerability Type", style="bold white")
            table.add_column("Severity", style="bold red")

            for r in results:
                table.add_row(
                    r["rule_id"],
                    os.path.basename(r["file"]),
                    str(r["line"]),
                    r["name"],
                    r["severity"]
                )
            self.console.print(table)
        else:
            print("Security Weaknesses Flagged:")
            for r in results:
                print(f"[{r['severity']}] Line {r['line']} in {os.path.basename(r['file'])}: {r['name']} ({r['rule_id']})")

    def run_fuzzer_only(self, target_path):
        self.print_banner()
        if not os.path.isfile(target_path):
            if HAS_RICH:
                self.console.print("[bold red]Error: Fuzzing requires a target file, not a directory.[/bold red]")
            else:
                print("Error: Fuzzing requires a target file, not a directory.")
            return

        if HAS_RICH:
            self.console.print(f"[bold yellow][RUN] Starting Sandbox Fuzzer on: {target_path}[/bold yellow]\n")
            with self.console.status("[bold green]Mutating inputs and monitoring process threads...") as status:
                time.sleep(1.0)
                result = self.fuzzer.fuzz_target(target_path)
            
            if result["vulnerable"]:
                self.console.print(f"[bold red][CRASH] Exploit Verification Success![/bold red]")
                self.console.print(Panel(
                    f"[bold red]CRASH TRIGGER CONFIRMED![/bold red]\n\n"
                    f"[bold white]Payload:[/bold white] {result['payload']}\n"
                    f"[bold white]Crash Vector:[/bold white] {result['trigger_reason']}\n"
                    f"[bold white]Exit Code:[/bold white] {result['exit_code']}",
                    title="Dynamic Analysis Findings", border_style="red"
                ))
            else:
                self.console.print("[bold green][OK] Fuzzing complete. No crashes triggered under current input mutations.[/bold green]")
        else:
            print(f"Starting Sandbox Fuzzer on: {target_path}\n")
            result = self.fuzzer.fuzz_target(target_path)
            if result["vulnerable"]:
                print("CRASH TRIGGER CONFIRMED!")
                print(f"Payload: {result['payload']}")
                print(f"Crash Vector: {result['trigger_reason']}")
                print(f"Exit Code: {result['exit_code']}")
            else:
                print("[OK] Fuzzing complete. No crashes triggered under current input mutations.")

    def build_dashboard(self, target_path, active_step, stats):
        """Constructs a high-fidelity visual dashboard panel layout."""
        # 1. System Telemetry Table
        telemetry = Table.grid(padding=1)
        telemetry.add_column(style="bold cyan", justify="right")
        telemetry.add_column(style="white")
        
        telemetry.add_row("SYSTEM STATE:", stats["state"])
        telemetry.add_row("TARGET FILE:", os.path.basename(target_path))
        telemetry.add_row("FILE TYPE:", os.path.splitext(target_path)[1].upper())
        telemetry.add_row("FILE SIZE:", f"{os.path.getsize(target_path) / 1024:.2f} KB")
        telemetry.add_row("ACTIVE LLM:", f"{self.reasoner.provider.upper()} ({'Live API' if self.reasoner.client else 'Local Mode'})")
        telemetry.add_row("THREAT COUNT:", f"[bold red]{stats['threats']}[/bold red]")

        panel_telemetry = Panel(telemetry, title="[bold cyan]SYSTEM TELEMETRY[/bold cyan]", border_style="cyan")

        # 2. Pipeline Execution Checklist
        pipeline = Table(box=None, padding=1)
        pipeline.add_column("Stage", style="bold yellow")
        pipeline.add_column("Process Name", style="white")
        pipeline.add_column("Status Flags", style="bold white")

        for idx, (stage_name, desc, status_text) in enumerate([
            ("Stage 1", "Static Vulnerability Scan", stats["stage1"]),
            ("Stage 2", "Dynamic Fuzzing Verification", stats["stage2"]),
            ("Stage 3", "AI Remediation Brain", stats["stage3"]),
            ("Stage 4", "Regression Suit & Promotion", stats["stage4"]),
        ]):
            # Highlight active stage
            style_row = "cyan" if (idx + 1) == active_step else "white"
            pipeline.add_row(stage_name, desc, status_text, style=style_row)

        panel_pipeline = Panel(pipeline, title="[bold cyan]SELF-HEALING CHECKLIST[/bold cyan]", border_style="cyan")

        # Return columns side-by-side
        return Columns([panel_telemetry, panel_pipeline], expand=True)

    def run_remediation_pipeline(self, target_path):
        self.print_banner()
        
        if not os.path.isfile(target_path):
            if HAS_RICH:
                self.console.print("[bold red]Error: Target path must be a specific file for autonomous repair.[/bold red]")
            else:
                print("Error: Target path must be a specific file for autonomous repair.")
            return

        if HAS_RICH:
            # Stats tracking for Live dashboard
            stats = {
                "state": "[bold yellow]INITIALIZING CRS...[/bold yellow]",
                "threats": "0",
                "stage1": "[dim]PENDING[/dim]",
                "stage2": "[dim]PENDING[/dim]",
                "stage3": "[dim]PENDING[/dim]",
                "stage4": "[dim]PENDING[/dim]"
            }

            # Initialize Live display context
            with Live(self.build_dashboard(target_path, 1, stats), refresh_per_second=4, console=self.console) as live:
                
                # --- Step 1: Scan ---
                stats["state"] = "[bold yellow]STATIC ANALYSIS ACTIVE[/bold yellow]"
                stats["stage1"] = "[yellow][RUN] RUNNING SCAN...[/yellow]"
                live.update(self.build_dashboard(target_path, 1, stats))
                
                time.sleep(1.0)
                static_warnings = self.analyzer.scan_file(target_path, self.reasoner)
                stats["threats"] = str(len(static_warnings))
                
                if len(static_warnings) > 0:
                    stats["stage1"] = f"[bold red][FAIL] {len(static_warnings)} WEAKNESSES FOUND[/bold red]"
                else:
                    stats["stage1"] = "[bold green][OK] SYSTEM CLEAN[/bold green]"
                live.update(self.build_dashboard(target_path, 2, stats))

                # --- Step 2: Fuzz ---
                stats["state"] = "[bold red]LAUNCHING SANDBOX FUZZER[/bold red]"
                stats["stage2"] = "[yellow][RUN] MUTATING PAYLOADS...[/yellow]"
                live.update(self.build_dashboard(target_path, 2, stats))

                time.sleep(1.2)
                fuzz_result = self.fuzzer.fuzz_target(target_path)
                
                if fuzz_result["vulnerable"]:
                    stats["stage2"] = "[bold red][CRASH] EXPLOIT CONFIRMED[/bold red]"
                    crash_payload = fuzz_result["payload"]
                else:
                    stats["stage2"] = "[bold green][OK] NO CRASH DETECTED[/bold green]"
                    crash_payload = "dummy_payload"
                live.update(self.build_dashboard(target_path, 3, stats))

                # --- Step 3: LLM Patch ---
                stats["state"] = "[bold cyan]AI PATCH REASONING ACTIVE[/bold cyan]"
                stats["stage3"] = "[yellow][RUN] QUERYING REASONER...[/yellow]"
                live.update(self.build_dashboard(target_path, 3, stats))

                with open(target_path, 'r', encoding='utf-8') as f:
                    orig_code = f.read()
                time.sleep(1.5)
                patch_response = self.reasoner.get_patch(orig_code, static_warnings, fuzz_result, target_path)

                if not patch_response["patched_code"]:
                    stats["stage3"] = "[bold red][FAIL] PATCH GENERATION FAILED[/bold red]"
                    stats["state"] = "[bold red]CRITICAL FAILURE[/bold red]"
                    live.update(self.build_dashboard(target_path, 3, stats))
                    
                    self.console.print("\n[bold red][FAIL] Stage 3 Failed. AI Reasoner could not draft a valid patch.[/bold red]")
                    if "explanation" in patch_response:
                        self.console.print(f"[bold yellow]Reason: {patch_response['explanation']}[/bold yellow]")
                    return
                
                stats["stage3"] = "[bold green][OK] PATCH DRAFTED[/bold green]"
                live.update(self.build_dashboard(target_path, 4, stats))

                # --- Step 4: Verification & Promotion ---
                stats["state"] = "[bold yellow]RUNNING HARNESS VERIFICATION[/bold yellow]"
                stats["stage4"] = "[yellow][RUN] COMPILING & TESTING...[/yellow]"
                live.update(self.build_dashboard(target_path, 4, stats))

                time.sleep(1.2)
                verify_result = self.harness.verify_patch(target_path, patch_response["patched_code"], crash_payload)

                if verify_result["success"]:
                    stats["stage4"] = "[bold green][OK] HARNESS SECURED[/bold green]"
                    stats["state"] = "[bold green][SHIELD ACTIVE / SECURED][/bold green]"
                    live.update(self.build_dashboard(target_path, 4, stats))
                    
                    self.console.print("\n[bold green][OK] Stage 4 Complete. Test Harness Verified Patch Integrity![/bold green]")
                    self.console.print(f"  +-- {verify_result['message']}\n")

                    # Show code diff block
                    self.console.print("[bold cyan][SHIELD] SECURE PATCH APPLIED (Source Code Diff Preview):[/bold cyan]")
                    self.console.print(Panel(
                        Syntax(patch_response["patched_code"], os.path.splitext(target_path)[1][1:], theme="monokai", line_numbers=True),
                        title=f"Remediated Build: {os.path.basename(target_path)}", border_style="green"
                    ))
                    
                    self.console.print("\n[bold green]*** SYSTEM STATUS: SHIELD ACTIVE / SECURED ***[/bold green]")
                else:
                    stats["stage4"] = "[bold red][FAIL] VERIFICATION REJECTED[/bold red]"
                    stats["state"] = "[bold red]HARNESS FAILURE[/bold red]"
                    live.update(self.build_dashboard(target_path, 4, stats))
                    
                    self.console.print(f"\n[bold red][FAIL] Stage 4 Failed: Regression Test Harness Rejected Patch![/bold red]")
                    self.console.print(f"  +-- Reason: {verify_result['error']}")

        else:
            # Minimal Console prints if Rich is missing (remains simple)
            print(f"⚡ Starting autonomous CRS loop on: {target_path}")
            static_warnings = self.analyzer.scan_file(target_path, self.reasoner)
            print(f"[1/4] Scan complete. Found {len(static_warnings)} weaknesses.")
            
            fuzz_result = self.fuzzer.fuzz_target(target_path)
            crash_payload = fuzz_result["payload"] if fuzz_result["vulnerable"] else "dummy"
            print(f"[2/4] Fuzzing complete. Crash trigger: {fuzz_result['vulnerable']}")
            
            with open(target_path, 'r', encoding='utf-8') as f:
                orig_code = f.read()
            patch_response = self.reasoner.get_patch(orig_code, static_warnings, fuzz_result, target_path)
            
            if not patch_response["patched_code"]:
                print("Error: AI reasoning could not generate patch.")
                return
            
            print("[3/4] AI patch reasoning generated.")
            verify_result = self.harness.verify_patch(target_path, patch_response["patched_code"], crash_payload)
            if verify_result["success"]:
                print("[4/4] Harness passed. Patch applied successfully!")
            else:
                print(f"Error: Harness rejected patch ({verify_result['error']})")


def main():
    parser = argparse.ArgumentParser(description="Agniveer Sentinel: Autonomous Self-Healing CLI Core Engine")
    parser.add_argument("mode", choices=["scan", "fuzz", "run"], help="Execution mode: scan, fuzz, or run pipeline")
    parser.add_argument("--target", required=True, help="Absolute or relative path to the target file/directory")

    args = parser.parse_args()

    cli = SentinelCLI()

    if args.mode == "scan":
        cli.run_static_scan(args.target)
    elif args.mode == "fuzz":
        cli.run_fuzzer_only(args.target)
    elif args.mode == "run":
        cli.run_remediation_pipeline(args.target)

if __name__ == "__main__":
    main()
