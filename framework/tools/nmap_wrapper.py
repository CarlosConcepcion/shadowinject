import socket
import concurrent.futures
from typing import Optional
from framework.models.scan_result import OpenPort


BANNER_GRAB_PORTS = {21, 22, 25, 80, 110, 135, 139, 143, 443, 445, 3306, 5432, 5900, 6379, 8080, 8443, 6667}


class PortScanner:
    def __init__(self, connect_timeout: float = 3.0, ports: list[int] = None):
        self.connect_timeout = connect_timeout
        self.ports = ports or [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
            3632, 5432, 5900, 5985, 5986, 6379, 6667, 8080, 8443, 9000, 27017,
        ]

    def _tcp_scan_port(self, target: str, port: int) -> Optional[OpenPort]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = self._guess_service(port)
                version = self._grab_banner(sock, target, port)
                sock.close()
                return OpenPort(port=port, protocol="tcp", state="open", service=service, version=version)
            sock.close()
            return None
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            return None

    def _grab_banner(self, sock: socket.socket, target: str, port: int) -> Optional[str]:
        try:
            sock.settimeout(2)

            if port == 80 or port == 8080 or port == 8443:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            elif port == 21:
                pass
            elif port == 25:
                pass
            elif port == 6667:
                pass
            else:
                return None

            data = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if not data:
                return None

            if port in (80, 8080, 8443):
                for line in data.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                http_line = data.split("\r\n")[0]
                return http_line[:120]

            if port == 21:
                return data.split("\r\n")[0][:120]

            if port == 25:
                return data.split("\r\n")[0][:120]

            if port == 6667:
                return data.split("\r\n")[0][:120]

            return data[:120]
        except Exception:
            return None

    def _guess_service(self, port: int) -> str:
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
            1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
            3632: "distcc", 5432: "postgresql", 5900: "vnc", 5985: "wsman", 5986: "wsmans",
            6379: "redis", 6667: "irc", 8080: "http-proxy", 8443: "https-alt",
            9000: "cslistener", 27017: "mongod",
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
