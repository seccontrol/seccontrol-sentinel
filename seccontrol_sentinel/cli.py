import sys
import os
import time
import json
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from seccontrol_sentinel import __version__
from seccontrol_sentinel.scanner.engine import MalwareScanner
from seccontrol_sentinel.monitor.fim import FileIntegrityMonitor
from seccontrol_sentinel.monitor.process_watcher import ProcessWatcher
from seccontrol_sentinel.perimeter.watchdog import PerimeterWatchdog
from seccontrol_sentinel.compliance.nis2 import NIS2Evaluator

console = Console()

def print_banner():
    banner = f"""[bold red]
  ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███╗   ██╗████████╗██████╗  ██████╗ ██╗     
  ██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██║     
  ███████╗█████╗  ██║     ██║     ██║   ██║██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║     
  ╚════██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║     
  ███████║███████╗╚██████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold red]
  [bold cyan]SecControl Sentinel v{__version__}[/bold cyan] - [dim]Endpoint Antivirus, FIM & Perimeter Exposure Watchdog[/dim]
  [green]Developed by SecControl SOC & Threat Intelligence Unit (https://seccontrol.it)[/green]
"""
    console.print(banner)

def cmd_scan(args):
    print_banner()
    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        console.print(f"[bold red]Error:[/bold red] Target path '{target_path}' does not exist.")
        sys.exit(1)

    console.print(f"[bold blue]Starting Malware & Heuristic Scan on:[/bold blue] [white]{target_path}[/white]")
    scanner = MalwareScanner(max_workers=args.threads)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=100)

        def progress_cb(done, total):
            if total > 0:
                progress.update(task, total=total, completed=done)

        findings = scanner.scan_directory(target_path, progress_callback=progress_cb)

    if findings:
        table = Table(title=f"🚨 Threats Detected ({len(findings)})", border_style="red")
        table.add_column("File Path", style="white", overflow="fold")
        table.add_column("Threat Name", style="bold red")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", style="bold magenta")

        for f in findings:
            table.add_row(f.filepath, f.threat_name, f.detection_type, f.severity)

        console.print(table)
    else:
        console.print(Panel("[bold green]✔ Scan Completed: Zero threats detected.[/bold green] Filesystem is clean.", border_style="green"))

def cmd_audit_perimeter(args):
    print_banner()
    console.print("[bold cyan]Auditing Local Network Listeners & Perimeter Sockets...[/bold cyan]\n")
    watchdog = PerimeterWatchdog()
    findings = watchdog.scan_listening_services()

    if findings:
        table = Table(title="⚠️ Insecure / Cleartext Listening Services", border_style="red")
        table.add_column("Port/Protocol", style="bold red")
        table.add_column("Service", style="yellow")
        table.add_column("Bound IP", style="cyan")
        table.add_column("Risk & Remediation", style="white", overflow="fold")

        for f in findings:
            table.add_row(
                str(f["port"]),
                f["service"],
                f["ip"],
                f"{f['risk']}\n[bold green]Fix:[/bold green] {f['remediation']}"
            )
        console.print(table)
    else:
        console.print("[bold green]✔ Perimeter Clean:[/bold green] No high-risk cleartext listeners (RFC 959 FTP 21, Telnet 23) active on host.")

    if args.domain:
        console.print(f"\n[bold cyan]Checking Authoritative DNS Cyber Hygiene for:[/bold cyan] [white]{args.domain}[/white]")
        dns_res = watchdog.check_domain_dns_hygiene(args.domain)
        d_table = Table(title=f"DNS Posture: {args.domain}", border_style="cyan")
        d_table.add_column("Check", style="white")
        d_table.add_column("Status", style="bold")
        d_table.add_column("Evaluation", style="dim")

        spf_status = "[green]Pass (Present)[/green]" if dns_res["spf_status"] == "present" else "[red]Fail (Missing)[/red]"
        dmarc_status = f"[green]Pass (p={dns_res['dmarc_policy']})[/green]" if dns_res["dmarc_policy"] in ("reject", "quarantine") else f"[red]Insecure (p={dns_res['dmarc_policy']})[/red]"

        d_table.add_row("SPF (RFC 7208)", spf_status, "Authorized mail server list in DNS")
        d_table.add_row("DMARC (RFC 7489)", dmarc_status, "Protection against sender domain spoofing and BEC")
        console.print(d_table)

def cmd_monitor(args):
    print_banner()
    paths = [os.path.abspath(p) for p in args.paths]
    console.print(f"[bold cyan]Initializing Real-Time File Integrity Monitor (FIM)...[/bold cyan]")
    fim = FileIntegrityMonitor(paths)
    count = fim.build_baseline()
    console.print(f"[green]✔ Baseline Established:[/green] {count} files cryptographically hashed (SHA-256).")
    console.print(f"[dim]Monitoring interval: {args.interval}s. Press Ctrl+C to stop.[/dim]\n")

    proc_watcher = ProcessWatcher()

    try:
        while True:
            time.sleep(args.interval)
            fim_alerts = fim.check_integrity()
            if fim_alerts:
                for alert in fim_alerts:
                    console.print(f"[{'red' if alert['severity'] == 'High' else 'yellow'}]🚨 [FIM ALERT] {alert['event']}: {alert['path']} - {alert['details']}[/]")

            proc_alerts = proc_watcher.inspect_active_processes()
            if proc_alerts:
                for p in proc_alerts:
                    console.print(f"[bold red]🚨 [PROCESS THREAT] PID {p['pid']} ({p['name']}): {p['reason']}[/bold red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring terminated by user.[/yellow]")

def cmd_report_nis2(args):
    print_banner()
    console.print("[bold cyan]Evaluating Host Cyber Hygiene Against NIS2 Directive (Art. 21 D.Lgs. 138/2024)...[/bold cyan]\n")

    scanner = MalwareScanner()
    av_findings = scanner.scan_directory(args.scan_dir) if args.scan_dir else []

    watchdog = PerimeterWatchdog()
    perim_findings = watchdog.scan_listening_services()
    dns_res = watchdog.check_domain_dns_hygiene(args.domain) if args.domain else {}

    evaluator = NIS2Evaluator()
    report = evaluator.evaluate_compliance(av_findings, [], perim_findings, dns_res)

    grade_color = "green" if report["grade"] == "A" else "yellow" if report["grade"] in ("B", "C") else "red"
    console.print(Panel(
        f"[bold {grade_color}]POSTURE GRADE: {report['grade']} (Score: {report['score']}/100)[/bold {grade_color}]\n"
        f"NIS2 Compliance Status: {'[bold green]ALIGNED[/bold green]' if report['nis2_aligned'] else '[bold red]NON-COMPLIANT (Action Required)[/bold red]'}\n"
        f"Framework: {report['framework']}",
        title="🛡️ SecControl NIS2 Executive Evaluation",
        border_style=grade_color
    ))

    if report["critical_issues"]:
        console.print("\n[bold red]Required Remediation Actions (Art. 21 Compliance):[/bold red]")
        for idx, issue in enumerate(report["critical_issues"], 1):
            console.print(f"  {idx}. {issue}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[green]Audit report saved to: {args.output}[/green]")

def cmd_gui(args):
    print_banner()
    console.print(f"[bold cyan]Launching SecControl Sentinel Dark Glassmorphic Web GUI on http://{args.host}:{args.port}...[/bold cyan]")
    from seccontrol_sentinel.gui.server import start_gui_server
    start_gui_server(host=args.host, port=args.port, open_browser=not args.no_browser)

def main():
    parser = argparse.ArgumentParser(
        prog="seccontrol-sentinel",
        description="SecControl Sentinel - Endpoint Detection, Antivirus & Perimeter Watchdog"
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan files/directories for malware and webshells")
    p_scan.add_argument("path", help="Path to file or directory to scan")
    p_scan.add_argument("--threads", type=int, default=4, help="Number of concurrent worker threads")

    # audit-perimeter
    p_perim = subparsers.add_parser("audit-perimeter", help="Audit local open ports and DNS spoofing postures")
    p_perim.add_argument("--domain", help="Company domain to evaluate for SPF/DMARC posture")

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Start real-time FIM and process watchdog")
    p_mon.add_argument("--paths", nargs="+", default=["/etc", "/var/www"], help="Directories to monitor")
    p_mon.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")

    # report-nis2
    p_nis2 = subparsers.add_parser("report-nis2", help="Generate NIS2 Art. 21 Cyber Hygiene Report")
    p_nis2.add_argument("--domain", help="Company domain to test")
    p_nis2.add_argument("--scan-dir", help="Directory to check for endpoint hygiene")
    p_nis2.add_argument("--output", help="Output JSON path")

    # gui
    p_gui = subparsers.add_parser("gui", help="Launch interactive dark glassmorphic web cockpit GUI")
    p_gui.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_gui.add_argument("--port", type=int, default=9876, help="Bind port (default: 9876)")
    p_gui.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "audit-perimeter":
        cmd_audit_perimeter(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "report-nis2":
        cmd_report_nis2(args)
    elif args.command == "gui":
        cmd_gui(args)

if __name__ == "__main__":
    main()
