from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from framework.models.scan_result import ScanResult, OpenPort, Endpoint
from framework.models.vulnerability import Vulnerability
from framework.models.exploit import Exploit, ExploitResult
from framework.tools.exploitdb_lookup import searcher as exploitdb


console = Console()


class Dashboard:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _rule(self, title: str):
        console.rule(title, style="cyan")

    def show_banner(self, target: str):
        console.clear()
        banner = Panel(
            Text.from_markup(
                "[bold cyan]SHADOWINJECT[/]\n"
                "[white]Exploit Generation Framework[/]\n"
                f"[dim]Target: {target}[/]"
            ),
            box=box.DOUBLE,
            border_style="cyan",
            padding=(1, 2),
        )
        console.print(banner)
        console.print()

    def show_phase(self, name: str, current: int, total: int):
        self._rule(f" Phase {current}/{total}: {name} ")

    def show_safety_ok(self, target: str, ranges: list[str]):
        ranges_str = ", ".join(ranges)
        panel = Panel(
            f"[green]Target {target} is in allowed range(s)[/]\n"
            f"[dim]Allowed: {ranges_str}[/]",
            title="[green]SAFETY PASS[/]",
            border_style="green",
        )
        console.print(panel)
        console.print()

    def show_ports(self, ports: list[OpenPort]):
        if not ports:
            console.print("[yellow]No open ports found.[/]\n")
            return
        table = Table(title="Open Ports", box=box.SIMPLE)
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="white")
        table.add_column("Version", style="dim")
        for p in ports:
            table.add_row(
                f"{p.port}/{p.protocol}",
                p.state,
                p.service or "unknown",
                p.version or "-",
            )
        console.print(table)
        console.print()

    def show_endpoints(self, endpoints: list[Endpoint]):
        if not endpoints:
            return
        table = Table(title="HTTP Endpoints", box=box.SIMPLE)
        table.add_column("Method", style="cyan")
        table.add_column("Path", style="white")
        table.add_column("Status", style="yellow")
        table.add_column("Size", style="dim")
        for ep in endpoints:
            table.add_row(
                ep.method,
                ep.path,
                str(ep.status_code or "?"),
                f"{ep.content_length or 0}b",
            )
        console.print(table)
        console.print()

    def show_vulnerabilities(self, vulns: list[Vulnerability]):
        if not vulns:
            console.print("[green]No vulnerabilities detected.[/]\n")
            return
        for i, v in enumerate(vulns, 1):
            confidence_pct = round(v.confidence * 100)
            color = "red" if v.confidence > 0.7 else "yellow"
            panel = Panel(
                f"[bold {color}]{v.vuln_type.value}[/]\n"
                f"[white]{v.description}[/]\n"
                f"[dim]Endpoint: [/][cyan]{v.endpoint}[/]"
                + (f"\n[dim]Parameter: [/][cyan]{v.parameter}[/]" if v.parameter else "")
                + (f"\n[dim]Evidence: [/]{v.evidence}" if v.evidence else "")
                + f"\n[dim]Confidence: [/]{confidence_pct}%"
                + (f"\n[dim]Remediation: [/]{v.remediation}" if v.remediation else ""),
                title=f"[{color}]Vulnerability #{i}[/]",
                border_style=color,
            )
            console.print(panel)
            console.print()

    def ask_selection(self, vulns: list[Vulnerability], open_ports: list) -> int:
        if not vulns:
            return -1
        console.print("[bold yellow]SELECT VULNERABILITY TO EXPLOIT[/]\n")
        for i, v in enumerate(vulns, 1):
            color = "red" if v.confidence > 0.7 else "yellow"
            port_info = ""
            ep = v.endpoint
            for p in open_ports:
                if str(p.port) in ep or p.service in ep.lower():
                    port_info = f" [dim](port {p.port} - {p.service or ''} {p.version or ''})[/]"
                    break
            console.print(
                f"  [{color}]{i}[/] {v.vuln_type.value} - {v.description[:80]}...{port_info}"
            )

        for v in vulns:
            ep = v.endpoint
            for p in open_ports:
                if str(p.port) in ep or (p.service and p.service in ep.lower()):
                    self._show_exploitdb(p)
                    break
        console.print()
        result = Prompt.ask(
            "[bold yellow]Choose vulnerability number (or 0 to skip, 'a' for all)[/]",
            default="0",
        )
        console.print()
        if result.lower() == "a":
            return -2
        try:
            choice = int(result)
            if 1 <= choice <= len(vulns):
                return choice - 1
            return -1
        except ValueError:
            return -1

    def _show_exploitdb(self, port):
        if not exploitdb.is_available():
            return
        query = port.service or ""
        if port.version:
            query += f" {port.version}"
        if not query.strip():
            return
        matches = exploitdb.search(query, max_results=3)
        if matches:
            table = Table(box=box.SIMPLE)
            table.add_column("ExploitDB Match", style="green")
            table.add_column("Type", style="dim")
            for m in matches:
                table.add_row(m["title"][:70], m["type"])
            console.print(table)
            console.print()

    def ask_confirmation(self, vulns: list[Vulnerability]) -> bool:
        if not vulns:
            return False
        primary = vulns[0]
        console.print(
            Panel(
                f"[yellow]Detected: {primary.vuln_type.value}[/]\n"
                f"[white]{primary.description}[/]\n"
                f"[dim]Endpoint: {primary.endpoint}[/]",
                title="[yellow]CONFIRMATION REQUIRED[/]",
                border_style="yellow",
            )
        )
        result = Prompt.ask(
            "[bold yellow]Generate and execute payload in sandbox?[/]",
            choices=["y", "n", "Y", "N"],
            default="n",
        )
        console.print()
        return result.lower() == "y"

    def show_exploit_generated(self, path: str):
        console.print(
            Panel(
                f"[green]PoC generated successfully[/]\n[dim]{path}[/]",
                title="[green]EXPLOIT GENERATED[/]",
                border_style="green",
            )
        )
        console.print()

    def show_exploit_result(self, result: ExploitResult):
        if result.success:
            panel = Panel(
                f"[bold green]PAYLOAD EXECUTED SUCCESSFULLY[/]\n"
                f"[dim]Execution time: {result.execution_time}s[/]\n"
                + (f"\n[white]Output:[/]\n{result.output}" if result.output else ""),
                title="[green]SANDBOX RESULT[/]",
                border_style="green",
            )
        else:
            panel = Panel(
                f"[bold red]EXECUTION FAILED[/]\n"
                + (f"\n[yellow]Error:[/]\n{result.error}" if result.error else "[dim]No output[/]"),
                title="[red]SANDBOX RESULT[/]",
                border_style="red",
            )
        console.print(panel)
        console.print()

    def show_error(self, msg: str):
        console.print(f"[red][ERROR] {msg}[/]\n")

    def show_warning(self, msg: str):
        console.print(f"[yellow][!] {msg}[/]\n")

    def show_status(self, msg: str):
        console.print(f"[cyan][*][/] {msg}")

    def show_summary(
        self,
        scan_result: ScanResult,
        vulnerabilities: list[Vulnerability],
        exploit: Optional[Exploit],
    ):
        self._rule(" SUMMARY ")
        table = Table(box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Target", scan_result.target)
        table.add_row("Open Ports", str(len(scan_result.open_ports)))
        table.add_row("Endpoints Found", str(len(scan_result.endpoints)))
        table.add_row("Vulnerabilities", str(len(vulnerabilities)))
        if exploit and exploit.result:
            status = "[green]SUCCESS[/]" if exploit.result.success else "[red]FAILED[/]"
            table.add_row("Sandbox Result", status)
        if exploit and exploit.script_filename:
            table.add_row("PoC Script", f"exploits/{exploit.script_filename}")
        console.print(table)

        log_file = f"logs/report_{scan_result.target.replace('.', '_')}.md"
        console.print(f"\n[dim]Report saved to: {log_file}[/]\n")
