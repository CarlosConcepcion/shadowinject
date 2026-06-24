import os
from pathlib import Path
from typing import Optional

PAT_DIR = Path(__file__).resolve().parents[2] / "payloads_reference"

VULN_DIR_MAP = {
    "SQL Injection": "SQL Injection",
    "Local File Inclusion": "File Inclusion",
    "Remote Code Execution": "Command Injection",
    "Cross-Site Scripting": "XSS Injection",
    "Server-Side Request Forgery": "Server Side Request Forgery",
    "Server-Side Template Injection": "Server Side Template Injection",
    "Insecure Direct Object Reference": "Insecure Direct Object References",
    "XXE": "XXE Injection",
    "NoSQL Injection": "NoSQL Injection",
    "LDAP Injection": "LDAP Injection",
    "Open Redirect": "Open Redirect",
    "SSRF": "Server Side Request Forgery",
    "Path Traversal": "Directory Traversal",
    "CRLF Injection": "CRLF Injection",
    "XXE Injection": "XXE Injection",
    "XSS": "XSS Injection",
    "LFI": "File Inclusion",
    "RCE": "Command Injection",
    "SQLi": "SQL Injection",
}


class PayloadReference:
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else PAT_DIR
        self._index: dict[str, list[dict]] | None = None

    def is_available(self) -> bool:
        return self.base_dir.exists()

    def build_index(self):
        self._index = {}
        if not self.is_available():
            return
        for vuln_dir in self.base_dir.iterdir():
            if not vuln_dir.is_dir() or vuln_dir.name.startswith("_"):
                continue
            category = vuln_dir.name
            self._index[category] = []
            self._index_vuln_dir(vuln_dir, category)

    def _index_vuln_dir(self, path: Path, category: str):
        for item in path.iterdir():
            if item.name.startswith("."):
                continue
            if item.is_file() and item.suffix.lower() in (".md", ".txt", ".py"):
                rel = item.relative_to(self.base_dir)
                self._index[category].append({
                    "name": item.stem,
                    "path": str(rel),
                    "ext": item.suffix,
                })
            elif item.is_dir() and item.name not in (".git", "__pycache__", "Images"):
                self._index_vuln_dir(item, category)

    def get_payload_files(self, vuln_type: str) -> list[dict]:
        if self._index is None:
            self.build_index()
        dir_name = VULN_DIR_MAP.get(vuln_type)
        if not dir_name:
            dir_name = self._guess_dir(vuln_type)
        if not dir_name:
            return []
        return self._index.get(dir_name, [])

    def _guess_dir(self, vuln_type: str) -> Optional[str]:
        if not self._index:
            return None
        lower = vuln_type.lower()
        for dir_name in self._index:
            if lower in dir_name.lower():
                return dir_name
        return None

    def read_file(self, rel_path: str, max_lines: int = 50) -> Optional[str]:
        full_path = self.base_dir / rel_path
        if not full_path.exists():
            return None
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append("... (truncated)")
                        break
                    lines.append(line.rstrip())
                return "\n".join(lines)
        except Exception:
            return None

    def get_relevant_payloads(self, vuln_type: str, max_files: int = 3, max_lines_per_file: int = 30) -> list[dict]:
        files = self.get_payload_files(vuln_type)
        results = []
        for f in files[:max_files]:
            content = self.read_file(f["path"], max_lines=max_lines_per_file)
            if content:
                results.append({
                    "source": f["path"],
                    "content": content,
                })
        return results

    def list_categories(self) -> list[str]:
        if self._index is None:
            self.build_index()
        return sorted(self._index.keys()) if self._index else []


reference = PayloadReference()
