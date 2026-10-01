"""
ASHWIN Endpoint Configuration (Phase 1, Section 7, Section 10).
Manages network endpoint parameters for remote servers (such as Moto G3).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class EndpointConfig:
    host: str = "10.202.197.15"
    port: int = 8443
    use_tls: bool = True
    pinned_ca_cert_pem: Optional[str] = None

    DEFAULT_MOTO_HOST: str = "10.202.197.15"
    DEFAULT_MOTO_PORT: int = 8443
    DEFAULT_MOTO_SERVER_CN: str = "MOTO-G3-STORAGE-ENDPOINT"

    def __post_init__(self):
        if not self.host or not self.host.strip():
            raise ValueError("Endpoint host cannot be blank")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Endpoint port must be between 1 and 65535 (got: {self.port})")

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def is_configured(self) -> bool:
        return bool(self.host and self.host.strip() and 1 <= self.port <= 65535)
