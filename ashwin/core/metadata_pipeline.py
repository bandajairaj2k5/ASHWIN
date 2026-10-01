"""
ASHWIN Metadata Pipeline (RULE-14).
Mandatory processing for all metadata before reaching model context:
source authentication -> authorization -> scope validation -> explicit field allowlist
-> secret scan / redaction -> classification (PROTECTED) -> Router gate -> routing / consent
"""

from typing import Dict, Any, List, Optional
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner

# Allowlists defined by RULE-14
V1_LAPTOP_METADATA_ALLOWLIST = {"name", "size", "date", "type"}
V1_MOTO_METADATA_ALLOWLIST = {"name", "size", "date", "type"}
V1_PROCESS_METADATA_ALLOWLIST = {"name", "pid"}  # RULE-14: No command line!
V1_DEVICE_METADATA_ALLOWLIST = {"name", "device_id", "status"}
V1_APP_METADATA_ALLOWLIST = {"name", "app_id"}


class MetadataPipeline:
    """
    Implements RULE-14 metadata filtering, scanning, classification, and gating.
    """

    def __init__(self, scanner: Optional[SecretScanner] = None):
        self.scanner = scanner or SecretScanner()

    def process_metadata(
        self,
        metadata: Dict[str, Any],
        source: SourceDomain,
        allowlist: Optional[set] = None,
        scope_authorized: bool = True,
        source_authenticated: bool = True
    ) -> ScannedClassifiedContext:
        """
        Processes raw metadata dictionary into a ScannedClassifiedContext.
        """
        # Step 1 & 2: Source authentication & Authorization
        if not source_authenticated or not scope_authorized:
            raise RouterGateError(f"RULE-14 Violation: Unauthorized or unauthenticated metadata source ({source.value}).")

        # Step 3: Explicit field allowlist filtering
        if allowlist is None:
            if source == SourceDomain.LAPTOP:
                allowlist = V1_LAPTOP_METADATA_ALLOWLIST
            elif source == SourceDomain.MOTO_STORAGE:
                allowlist = V1_MOTO_METADATA_ALLOWLIST
            else:
                allowlist = set()

        filtered_metadata = {}
        for key in sorted(allowlist):
            if key in metadata:
                filtered_metadata[key] = metadata[key]

        # Explicitly drop command lines if present (RULE-14)
        filtered_metadata.pop("command_line", None)
        filtered_metadata.pop("cmdline", None)
        filtered_metadata.pop("args", None)

        # Format metadata into sorted text representation for model consumption
        raw_text_repr = ", ".join(f"{k}={filtered_metadata[k]}" for k in sorted(filtered_metadata.keys()))

        # Step 4: Secret scan / Redaction (RULE-09)
        redacted_text, scan_summary, detected_class = self.scanner.scan_and_redact(raw_text_repr)

        if not scan_summary.get("healthy", False):
            raise RouterGateError("RULE-14 / RULE-09: Metadata secret scanning failed.")

        # Step 5 & 6: Classification (PROTECTED per Section 4.3 & RULE-14) & Router gate wrapping
        context = ScannedClassifiedContext(
            content=redacted_text,
            data_class=DataClass.PROTECTED,
            source=source,
            cloud_approved=False,
            scanned=True,
            scan_summary=scan_summary,
            metadata=filtered_metadata
        )

        return context
