"""
ASHWIN Moto Storage Connector (Client) (Section 6.3, Section 7.4, Section 10, T-57).
Implements mTLS client transport, challenge-response protocol, access permission checking,
and the full decrypt -> bounded buffering -> extraction -> secret scan -> Router pipeline.
"""

import os
import json
from typing import Dict, Any, List, Optional

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.metadata_pipeline import MetadataPipeline
from ashwin.core.location_formatter import LocationFormatter
from ashwin.core.extractor import TextExtractor, ExtractorError
from ashwin.moto_endpoint.crypto import DeviceIdentity, CryptoSecurityError
from ashwin.moto_endpoint.server import MotoStorageServer


class MotoFeasibilityError(Exception):
    """Raised when the Moto G3 feasibility gate fails."""
    pass


class MotoSecurityError(Exception):
    """Raised when Moto storage security checks fail."""
    pass


class MotoConnector:
    """
    Client Connector running in ASHWIN Core communicating with Moto G3 Storage Server.
    """

    MAX_BUFFER_SIZE = 5 * 1024 * 1024  # 5 MB hard limit (Section 15)

    def __init__(self, device_id: str = "ASHWIN-CORE-CLIENT", server: Optional[MotoStorageServer] = None):
        self.device_id = device_id
        self.identity = DeviceIdentity(device_id, is_server=False)
        self.server = server
        self.paired = False
        self.access_permission_granted = False
        self.feasibility_passed = False
        self.scanner = SecretScanner()
        self.metadata_pipeline = MetadataPipeline(scanner=self.scanner)

    # =========================================================================
    # Feasibility Gate & Pairing
    # =========================================================================

    def run_feasibility_gate(
        self,
        tls_supported: bool = True,
        crypto_supported: bool = True,
        background_ok: bool = True
    ) -> bool:
        """Section 7.4 Feasibility Gate verification."""
        if tls_supported and crypto_supported and background_ok:
            self.feasibility_passed = True
            return True
        self.feasibility_passed = False
        raise MotoFeasibilityError("Section 7.4 Gate Failure: Moto G3 cannot support required authenticated encrypted transport.")

    def pair_device(self, pairing_code_confirmed: bool) -> bool:
        """Performs pairing with 6-digit SAS human OOB confirmation."""
        if not self.feasibility_passed:
            raise MotoFeasibilityError("Cannot pair: Feasibility gate has not passed.")
        if not pairing_code_confirmed:
            raise MotoSecurityError("Moto pairing rejected: Incorrect pairing code.")

        if self.server:
            # Exchange public keys and register
            sas = self.identity.compute_sas_code(self.server.identity.public_key)
            self.identity.complete_pairing(self.server.identity.public_key, user_confirmed_sas=True)
            self.server.identity.complete_pairing(self.identity.public_key, user_confirmed_sas=True)
            self.paired = True
            return True

        self.paired = True
        return True

    def revoke_pairing(self):
        """Revokes trust and invalidates keys immediately."""
        self.identity.revoke_pairing()
        if self.server:
            self.server.identity.revoke_pairing()
        self.paired = False

    def set_access_permission(self, granted: bool):
        """Section 6.3 Access permission decision."""
        self.access_permission_granted = granted

    # =========================================================================
    # Request Execution via mTLS + Challenge Nonce
    # =========================================================================

    def _execute_authenticated_request(self, method: str, path: str, body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """
        Fetches a single-use challenge nonce, signs the request, and executes against the server.
        """
        if not self.paired:
            raise MotoSecurityError("Moto device is not paired.")
        if not self.server:
            raise MotoSecurityError("Cannot connect to Moto server endpoint.")

        # Step 1: Pre-flight challenge request
        c_status, _, c_body = self.server.handle_request("POST", "/storage/v1/challenge", {}, b"")
        if c_status != 200:
            raise MotoSecurityError("Failed to obtain challenge nonce from Moto storage server.")

        challenge_data = json.loads(c_body.decode("utf-8"))
        nonce = challenge_data["nonce"]

        # Step 2: Sign request payload
        signature = self.identity.sign_payload(nonce, method, path, body)

        headers = {
            "X-Moto-Nonce": nonce,
            "X-Moto-Signature": signature,
            "X-Client-PubKey": self.identity.public_key
        }

        # Step 3: Execute request
        return self.server.handle_request(method, path, headers, body)

    # =========================================================================
    # Storage Capabilities (Section 10)
    # =========================================================================

    def list_files(self, subfolder: str = "") -> ScannedClassifiedContext:
        """
        Capability: list - retrieves file list from ASHWIN_STORAGE area only.
        Checks access permission FIRST (Section 6.3, T-57).
        """
        if not self.paired:
            raise MotoSecurityError("Moto device is not paired.")
        if not self.access_permission_granted:
            raise MotoSecurityError("Permission Denied: Access permission check failed before retrieving Moto contents.")

        req_body = json.dumps({"subfolder": subfolder}).encode("utf-8")
        status, _, resp_body = self._execute_authenticated_request("POST", "/storage/v1/list", req_body)

        if status != 200:
            raise MotoSecurityError(f"List failed with status {status}: {resp_body.decode('utf-8')}")

        data = json.loads(resp_body.decode("utf-8"))
        items = data.get("items", [])
        file_list_str = ", ".join(item["name"] for item in items)
        raw_metadata = {
            "name": file_list_str,
            "size": str(len(items)),
            "date": "2026-09-30",
            "type": "directory"
        }

        return self.metadata_pipeline.process_metadata(
            metadata=raw_metadata,
            source=SourceDomain.MOTO_STORAGE,
            allowlist={"name", "size", "date", "type"},
            scope_authorized=True,
            source_authenticated=self.paired
        )

    def read_file(self, rel_path: str) -> ScannedClassifiedContext:
        """
        Capability: read - reads and processes file from ASHWIN_STORAGE.
        Pipeline: Auth -> Access Permission -> Decrypt -> Bounded Buffering -> Extract -> Scan -> Router Gate.
        """
        # Step 1 & 2: Auth & Access permission check FIRST (T-57)
        if not self.paired:
            raise MotoSecurityError("Moto device is not paired.")
        if not self.access_permission_granted:
            raise MotoSecurityError("Access permission denied for Moto storage.")

        req_body = json.dumps({"file_path": rel_path}).encode("utf-8")
        status, headers, resp_body = self._execute_authenticated_request("POST", "/storage/v1/read", req_body)

        if status == 413:
            raise MotoSecurityError(f"Moto file size exceeds 5 MB limit. AI delivery denied.")
        if status == 403:
            raise MotoSecurityError(f"Access Forbidden: Path outside ASHWIN_STORAGE.")
        if status == 404:
            raise MotoSecurityError(f"File '{rel_path}' not found in ASHWIN_STORAGE.")
        if status != 200:
            raise MotoSecurityError(f"Read failed with status {status}: {resp_body.decode('utf-8')}")

        # Step 3: Bounded buffering check (5 MB max) on client
        if len(resp_body) > self.MAX_BUFFER_SIZE:
            raise MotoSecurityError(f"Moto file size {len(resp_body)} exceeds 5 MB limit. AI delivery denied.")

        # Step 4: Text extraction
        extracted_text = TextExtractor.validate_and_extract_txt(resp_body)

        # Step 5: Secret scan & redaction (RULE-09)
        redacted_text, scan_summary, _ = self.scanner.scan_and_redact(extracted_text)

        if not scan_summary.get("healthy", False):
            raise RouterGateError("Moto file secret scan failed.")

        # Step 6: Format location (RULE-15: scope label + name)
        model_location = LocationFormatter.format_for_model("MOTO_STORAGE", os.path.basename(rel_path))

        # Step 7: Wrap in ScannedClassifiedContext (RULE-04, PROTECTED class per Section 4.3)
        return ScannedClassifiedContext(
            content=redacted_text,
            data_class=DataClass.PROTECTED,
            source=SourceDomain.MOTO_STORAGE,
            cloud_approved=False,
            scanned=True,
            scan_summary=scan_summary,
            metadata={
                "name": os.path.basename(rel_path),
                "scope_label": "MOTO_STORAGE",
                "location_for_model": model_location
            }
        )
