import json
from framework.models.scan_result import ScanResult
from framework.models.vulnerability import Vulnerability, VulnType
from framework.tools.llm_client import LLMClient
from framework.tools.payload_reference import reference as payload_ref


ANALYSIS_SYSTEM_PROMPT = """You are a Senior Application Security Engineer performing a penetration test.

Given the scan results below, identify all security vulnerabilities. For each finding:
1. Classify the vulnerability type (SQL Injection, LFI, RCE, XSS, SSRF, IDOR, Information Disclosure, or Other)
2. Describe the vulnerability in detail
3. Identify the affected endpoint and parameter
4. Provide specific evidence from the response data
5. Rate confidence from 0.0 to 1.0
6. Suggest remediation

Focus on OWASP Top 10 vulnerabilities. Be precise and technical.

Return a JSON object with a single key "vulnerabilities" containing an array of objects with these fields:
- vuln_type: string (one of: "SQL Injection", "Local File Inclusion", "Remote Code Execution", "Cross-Site Scripting", "Server-Side Request Forgery", "Insecure Direct Object Reference", "Information Disclosure", "Other")
- description: string
- endpoint: string
- parameter: string or null
- method: string
- confidence: float (0.0 to 1.0)
- evidence: string or null
- remediation: string or null

If no vulnerabilities are found, return {"vulnerabilities": []}."""


class AnalyzerAgent:
    def __init__(self, config: dict, llm_client: LLMClient):
        self.config = config
        self.llm_client = llm_client

    def analyze(self, scan_result: ScanResult) -> list[Vulnerability]:
        user_prompt = self._build_prompt(scan_result)
        raw = self.llm_client.chat(ANALYSIS_SYSTEM_PROMPT, user_prompt, output_json=True)
        return self._parse_response(raw, scan_result.target)

    def _get_payload_reference_block(self) -> str:
        if not payload_ref.is_available():
            return ""
        categories = payload_ref.list_categories()
        return (
            "\nReference payloads available for techniques:\n"
            + "\n".join(f"  - {cat}" for cat in categories)
            + "\n\nUse these techniques as inspiration when analyzing."
        )

    def _build_prompt(self, scan_result: ScanResult) -> str:
        lines = [
            f"Target: {scan_result.target}",
            f"Hostname: {scan_result.hostname or 'N/A'}",
            "",
            "Open Ports:",
        ]
        for p in scan_result.open_ports:
            ver = f" ({p.version})" if p.version else ""
            lines.append(f"  - {p.port}/{p.protocol}  {p.service or 'unknown'}{ver}")
        ref_block = self._get_payload_reference_block()
        if ref_block:
            lines.append(ref_block)
        lines.append("")
        lines.append("HTTP Endpoints:")
        for ep in scan_result.endpoints:
            preview = (ep.response_preview or "")[:300]
            lines.append(f"  [{ep.method}] {ep.path} -> {ep.status_code}")
            if preview:
                lines.append(f"    Response: {preview}")
        return "\n".join(lines)

    def _parse_response(self, raw: dict, target: str) -> list[Vulnerability]:
        vulns = []
        raw_list = raw.get("vulnerabilities", [])
        for item in raw_list:
            try:
                vuln_type = VulnType(item.get("vuln_type", "Other"))
            except ValueError:
                vuln_type = VulnType.OTHER
            vulns.append(Vulnerability(
                vuln_type=vuln_type,
                description=item.get("description", ""),
                endpoint=item.get("endpoint", target),
                parameter=item.get("parameter"),
                method=item.get("method", "GET"),
                confidence=item.get("confidence", 0.0),
                evidence=item.get("evidence"),
                remediation=item.get("remediation"),
            ))
        return vulns
