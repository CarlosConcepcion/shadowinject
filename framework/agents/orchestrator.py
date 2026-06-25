import time
from framework.safety.ip_restrictor import SafetySwitch
from framework.tools.nmap_wrapper import PortScanner
from framework.tools.http_client import HttpClient
from framework.tools.llm_client import LLMClient
from framework.tools.docker_client import DockerClient
from framework.agents.analyzer_agent import AnalyzerAgent
from framework.agents.exploit_generator_agent import ExploitGeneratorAgent
from framework.dashboard.terminal_ui import Dashboard
from framework.reporting.log_manager import LogManager
from framework.models.scan_result import ScanResult, OpenPort
from framework.models.vulnerability import Vulnerability
from framework.models.exploit import Exploit
from framework.reporting.log_manager import LogManager


class PentestFramework:
    def __init__(self, target: str, config: dict, verbose: bool = False):
        self.target = target
        self.config = config
        self.verbose = verbose

        self.safety = SafetySwitch(
            config.get("target", {}).get("allowed_cidrs", ["192.168.0.0/16"])
        )
        scan_cfg = config.get("scan", {})
        self.scanner = PortScanner(
            connect_timeout=scan_cfg.get("connect_timeout", 3.0),
            ports=scan_cfg.get("ports_common"),
        )
        self.http_client = HttpClient()
        llm_cfg = config.get("llm", {})
        self.llm_client = LLMClient(
            provider=llm_cfg.get("provider", "groq"),
            model=llm_cfg.get("model", "llama-3.3-70b-versatile"),
            temperature=llm_cfg.get("temperature", 0.1),
            max_tokens=llm_cfg.get("max_tokens", 4096),
        )
        sandbox_cfg = config.get("sandbox", {})
        self.docker = DockerClient(
            image=sandbox_cfg.get("docker_image", "python:3.11-slim"),
            timeout=sandbox_cfg.get("container_timeout", 30),
            network_disabled=sandbox_cfg.get("network_disabled", True),
        )
        self.analyzer = AnalyzerAgent(config, self.llm_client)
        self.exploit_generator = ExploitGeneratorAgent(config, self.llm_client)
        self.dashboard = Dashboard(verbose=verbose)
        self.logger = LogManager(config.get("logging", {}))

        self.scan_result: ScanResult = ScanResult(target=target)
        self.vulnerabilities: list[Vulnerability] = []
        self.exploit: Exploit | None = None
        self._selected_vuln_index: int = -1

    def run(self):
        self.dashboard.show_banner(self.target)
        try:
            self._phase_safety()
            self._phase_recon()
            self._phase_analysis()
            self._phase_verification()
            self._phase_exploit_generation()
            self._phase_sandbox()
            self._phase_reporting()
            self.dashboard.show_summary(
                self.scan_result, self.vulnerabilities, self.exploit
            )
        except PermissionError as e:
            self.dashboard.show_error(f"Safety Switch: {e}")
        except KeyboardInterrupt:
            self.dashboard.show_warning("Interrupted by user.")
        except Exception as e:
            self.dashboard.show_error(f"Unexpected error: {e}")
            if self.verbose:
                raise

    def _phase_safety(self):
        self.dashboard.show_phase("SAFETY CHECK", 1, 6)
        self.safety.assert_target_allowed(self.target)
        ranges = self.safety.get_allowed_ranges()
        self.dashboard.show_safety_ok(self.target, ranges)

    def _phase_recon(self):
        self.dashboard.show_phase("RECONNAISSANCE", 2, 6)

        self.dashboard.show_status("Scanning ports...")
        open_ports = self.scanner.scan(self.target)
        self.scan_result.open_ports = open_ports
        self.dashboard.show_ports(open_ports)

        if open_ports:
            http_ports = [p.port for p in open_ports if p.port in (80, 443, 8080, 8443)]
            if http_ports:
                self.dashboard.show_status("Probing HTTP endpoints...")
                paths = self.config.get("scan", {}).get(
                    "http_paths",
                    ["/", "/api/v1/users", "/api/v1/login", "/admin", "/.env"],
                )
                all_endpoints = []
                for port in http_ports:
                    eps = self.http_client.probe_http(
                        self.target, port, paths, ssl=(port in (443, 8443))
                    )
                    all_endpoints.extend(eps)
                self.scan_result.endpoints = all_endpoints
                self.dashboard.show_endpoints(all_endpoints)
        else:
            self.dashboard.show_warning("No open ports found.")

    def _phase_analysis(self):
        self.dashboard.show_phase("VULNERABILITY ANALYSIS", 3, 6)
        self.dashboard.show_status("Running AI analysis...")

        self.vulnerabilities = self.analyzer.analyze(self.scan_result)
        self.dashboard.show_vulnerabilities(self.vulnerabilities)

    def _phase_verification(self):
        self.dashboard.show_phase("HUMAN VERIFICATION", 4, 6)
        if not self.vulnerabilities:
            self.dashboard.show_warning("No vulnerabilities detected.")
            self._selected_vuln_index = -1
            return
        self._selected_vuln_index = self.dashboard.ask_selection(
            self.vulnerabilities, self.scan_result.open_ports
        )

    def _phase_exploit_generation(self):
        self.dashboard.show_phase("EXPLOIT GENERATION", 5, 6)
        if self._selected_vuln_index == -1:
            self.dashboard.show_warning("Skipping exploit generation.")
            return
        if self._selected_vuln_index == -2:
            targets = self.vulnerabilities
        else:
            targets = [self.vulnerabilities[self._selected_vuln_index]]

        for vuln in targets:
            self.dashboard.show_status(f"Generating PoC for {vuln.vuln_type.value} on {vuln.endpoint}...")
            self.exploit = self.exploit_generator.generate(vuln)
            path = DockerClient.write_script(self.exploit)
            self.dashboard.show_exploit_generated(path)

    def _phase_sandbox(self):
        self.dashboard.show_phase("SANDBOX EXECUTION", 6, 6)
        if not self.exploit:
            return

        if not self.docker.is_available():
            self.dashboard.show_warning(
                "Docker is not available. Skipping sandbox execution."
            )
            self.dashboard.show_status(
                "PoC script saved to exploits/ directory for manual review."
            )
            return

        self.dashboard.show_status("Executing in isolated Docker container...")
        script_path = f"exploits/{self.exploit.script_filename}"
        result = self.docker.execute_script(self.exploit, script_path)
        self.exploit.result = result
        self.dashboard.show_exploit_result(result)

    def _phase_reporting(self):
        self.logger.save_report(
            target=self.target,
            scan_result=self.scan_result,
            vulnerabilities=self.vulnerabilities,
            exploit=self.exploit,
        )
