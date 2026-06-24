from pydantic import BaseModel
from typing import Optional


class OpenPort(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None


class Endpoint(BaseModel):
    path: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    response_preview: Optional[str] = None
    headers: Optional[dict] = None


class ScanResult(BaseModel):
    target: str
    hostname: Optional[str] = None
    open_ports: list[OpenPort] = []
    endpoints: list[Endpoint] = []
    os_detection: Optional[str] = None
    raw_scan_summary: Optional[str] = None
