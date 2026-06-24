import requests
from typing import Optional
from urllib.parse import urljoin
from framework.models.scan_result import Endpoint


class HttpClient:
    def __init__(self, timeout: float = 10.0, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.session.max_redirects = 5

    def probe_endpoint(
        self, base_url: str, path: str, method: str = "GET"
    ) -> Optional[Endpoint]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            body_preview = resp.text[:500] if resp.text else None
            return Endpoint(
                path=path,
                method=method,
                status_code=resp.status_code,
                content_length=len(resp.content),
                response_preview=body_preview,
                headers=dict(resp.headers),
            )
        except (requests.RequestException, ConnectionError):
            return None

    def probe_http(
        self, target: str, port: int, paths: list[str], ssl: bool = False
    ) -> list[Endpoint]:
        scheme = "https" if ssl else "http"
        base_url = f"{scheme}://{target}:{port}"
        endpoints: list[Endpoint] = []
        for path in paths:
            ep = self.probe_endpoint(base_url, path)
            if ep is not None:
                endpoints.append(ep)
        return endpoints

    def probe_ports(
        self, target: str, ports: list[int], paths: list[str]
    ) -> dict[int, list[Endpoint]]:
        results: dict[int, list[Endpoint]] = {}
        for port in ports:
            eps = self.probe_http(target, port, paths, ssl=(port == 443))
            if eps:
                results[port] = eps
        return results
