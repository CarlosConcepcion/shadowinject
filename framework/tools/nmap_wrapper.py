import socket
import concurrent.futures
from typing import Optional
from framework.models.scan_result import OpenPort


class PortScanner:
    def __init__(self, connect_timeout: float = 3.0, ports: list[int] = None):
        self.connect_timeout = connect_timeout
        self.ports = ports or [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
            5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 27017,
        ]

    def _tcp_scan_port(self, target: str, port: int) -> Optional[OpenPort]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                service = self._guess_service(port)
                return OpenPort(port=port, protocol="tcp", state="open", service=service)
            return None
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            return None

    def _guess_service(self, port: int) -> str:
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
            1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
            5432: "postgresql", 5900: "vnc", 5985: "wsman", 5986: "wsmans",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9000: "cslistener",
            27017: "mongod",
        }
        return common_ports.get(port, "unknown")

    def scan(self, target: str) -> list[OpenPort]:
        open_ports: list[OpenPort] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            fut_map = {
                executor.submit(self._tcp_scan_port, target, port): port
                for port in self.ports
            }
            for future in concurrent.futures.as_completed(fut_map):
                result = future.result()
                if result:
                    open_ports.append(result)
        open_ports.sort(key=lambda p: p.port)
        return open_ports

    def scan_range(self, target: str, port_range: range) -> list[OpenPort]:
        open_ports: list[OpenPort] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            fut_map = {
                executor.submit(self._tcp_scan_port, target, port): port
                for port in port_range
            }
            for future in concurrent.futures.as_completed(fut_map):
                result = future.result()
                if result:
                    open_ports.append(result)
        open_ports.sort(key=lambda p: p.port)
        return open_ports
