"""
ASHWIN Input Classifier & Ingestion Pipeline (Phase 3 / Stage B, Section 4.3, Section 5, RULE-03, RULE-04).
Implements the classification policy where typed input and STT transcriptions are PROTECTED by default.
"""

from typing import Dict, Any, Optional
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner


class InputClassifier:
    """
    Ingests and classifies input sources, running SecretScanner and assigning DataClass.
    Default for typed user messages and voice STT output is PROTECTED (Section 4.3).
    """

    def __init__(self, scanner: Optional[SecretScanner] = None):
        self.scanner = scanner or SecretScanner()

    def process_user_input(
        self,
        raw_text: str,
        source: SourceDomain = SourceDomain.PHONE,
        is_stt: bool = False,
        cloud_approved: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScannedClassifiedContext:
        """
        Ingests user input (typed or STT).
        1. Runs SecretScanner to detect/redact secrets.
        2. Assigns DataClass.PROTECTED by default.
        3. If unredacted HIGHLY_PROTECTED secrets exist or scanner is unhealthy, raises SecurityViolation / RouterGateError.
        4. Returns validated ScannedClassifiedContext.
        """
        if not self.scanner.is_healthy():
            raise RouterGateError("Classification rejected: SecretScanner is unhealthy.")

        # Step 1: Scan and Redact
        redacted_content, scan_summary, assessed_class = self.scanner.scan_and_redact(raw_text)

        # Step 2: Enforce Default Classification (PROTECTED for user typed/STT per Section 4.3)
        final_class = DataClass.PROTECTED
        if assessed_class == DataClass.HIGHLY_PROTECTED:
            final_class = DataClass.HIGHLY_PROTECTED

        # Metadata tracking
        meta = dict(metadata or {})
        meta["input_type"] = "STT" if is_stt else "TYPED_TEXT"
        meta["source_domain"] = source.value
        meta["redaction_count"] = scan_summary.get("redaction_count", 0)

        # Step 3: Wrap into ScannedClassifiedContext (Constructor enforces RULE-03 and RULE-04)
        return ScannedClassifiedContext(
            content=redacted_content,
            data_class=final_class,
            source=source,
            cloud_approved=cloud_approved,
            scanned=True,
            scan_summary=scan_summary,
            metadata=meta
        )

    def process_external_content(
        self,
        content: str,
        source: SourceDomain,
        default_class: DataClass = DataClass.PROTECTED,
        cloud_approved: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScannedClassifiedContext:
        """
        Ingests external content (documents, metadata, connector output).
        """
        if not self.scanner.is_healthy():
            raise RouterGateError("Classification rejected: SecretScanner is unhealthy.")

        redacted_content, scan_summary, assessed_class = self.scanner.scan_and_redact(content)

        final_class = default_class
        if assessed_class == DataClass.HIGHLY_PROTECTED:
            final_class = DataClass.HIGHLY_PROTECTED

        return ScannedClassifiedContext(
            content=redacted_content,
            data_class=final_class,
            source=source,
            cloud_approved=cloud_approved,
            scanned=True,
            scan_summary=scan_summary,
            metadata=metadata or {}
        )
