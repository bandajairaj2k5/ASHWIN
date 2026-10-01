"""
ASHWIN Credential & Identity Store (Phase 1, Section 7, Section 12, RULE-02, RULE-12).
Manages secure in-memory credential lifecycle for Cloud AI and Moto Client Identities.
"""

from typing import Optional
from ashwin.core.endpoint_config import EndpointConfig


class CredentialStore:
    """
    Core Credential Store enforcing credential isolation and revocation semantics.
    """

    def __init__(self):
        self._cloud_api_key: Optional[str] = None
        self._moto_transport_cert_pem: Optional[str] = None
        self._moto_transport_key_pem: Optional[str] = None
        self._moto_app_public_key: Optional[str] = None
        self._moto_app_private_key: Optional[bytes] = None
        self._moto_pinned_peer_public_key: Optional[str] = None
        self._moto_session_key: Optional[bytes] = None
        self._moto_is_paired: bool = False
        self._endpoint_config: EndpointConfig = EndpointConfig()

    # Cloud AI API Key
    def set_cloud_api_key(self, api_key: str):
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be blank")
        self._cloud_api_key = api_key.strip()

    def get_cloud_api_key(self) -> Optional[str]:
        return self._cloud_api_key

    def has_cloud_api_key(self) -> bool:
        return bool(self._cloud_api_key)

    def clear_cloud_api_key(self):
        self._cloud_api_key = None

    # Endpoint Configuration
    def set_endpoint_config(self, config: EndpointConfig):
        self._endpoint_config = config

    def get_endpoint_config(self) -> EndpointConfig:
        return self._endpoint_config

    # Moto Transport Identity
    def set_moto_transport_identity(self, cert_pem: str, key_pem: str):
        if not cert_pem or not key_pem:
            raise ValueError("Certificate and Key PEM cannot be blank")
        self._moto_transport_cert_pem = cert_pem
        self._moto_transport_key_pem = key_pem

    def get_moto_transport_cert_pem(self) -> Optional[str]:
        return self._moto_transport_cert_pem

    def get_moto_transport_key_pem(self) -> Optional[str]:
        return self._moto_transport_key_pem

    # Moto Application Pairing Identity
    def set_moto_application_identity(self, public_key_hex: str, private_key_bytes: bytes):
        self._moto_app_public_key = public_key_hex
        self._moto_app_private_key = bytes(private_key_bytes)

    def get_moto_app_public_key(self) -> Optional[str]:
        return self._moto_app_public_key

    def get_moto_app_private_key(self) -> Optional[bytes]:
        return bytes(self._moto_app_private_key) if self._moto_app_private_key else None

    def complete_moto_pairing(self, pinned_peer_public_key: str, session_key: bytes):
        self._moto_pinned_peer_public_key = pinned_peer_public_key
        self._moto_session_key = bytes(session_key)
        self._moto_is_paired = True

    def is_moto_paired(self) -> bool:
        return self._moto_is_paired

    def get_moto_pinned_peer_public_key(self) -> Optional[str]:
        return self._moto_pinned_peer_public_key

    def get_moto_session_key(self) -> Optional[bytes]:
        return bytes(self._moto_session_key) if self._moto_session_key else None

    # Revocation
    def revoke_moto_pairing(self):
        self._moto_pinned_peer_public_key = None
        self._moto_session_key = None
        self._moto_is_paired = False

    def clear_all(self):
        self.clear_cloud_api_key()
        self.revoke_moto_pairing()
        self._moto_transport_cert_pem = None
        self._moto_transport_key_pem = None
        self._moto_app_public_key = None
        self._moto_app_private_key = None
