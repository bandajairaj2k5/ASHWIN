"""
ASHWIN Gmail Connector (Section 12, Section 6.6).
"""

from typing import Dict, Any, Set
from ashwin.core.models import DataClass, SourceDomain, ScannedClassifiedContext, RouterGateError, SecurityViolation
from ashwin.connectors.base import BaseConnector


class GmailConnector(BaseConnector):

    def __init__(self):
        super().__init__(SourceDomain.GMAIL)

    @property
    def declared_operations(self) -> Set[str]:
        return {"read_email", "search_email", "send_email"}

    @property
    def metadata_allowlist(self) -> Set[str]:
        return {"sender", "subject", "date"}

    def _execute_operation(
        self,
        operation_name: str,
        params: Dict[str, Any],
        user_confirmed: bool
    ) -> ScannedClassifiedContext:
        if operation_name == "send_email":
            # Section 6.6: Sensitive action requires explicit user confirmation
            if not user_confirmed:
                raise SecurityViolation("Section 6.6 Violation: send_email requires explicit user confirmation.")
            content = f"Email sent to {params.get('to')} with subject '{params.get('subject')}'."
        else:
            content = f"Gmail content for {operation_name} query '{params.get('query', '')}'"

        redacted_text, scan_summary, _ = self.scanner.scan_and_redact(content)

        return ScannedClassifiedContext(
            content=redacted_text,
            data_class=DataClass.PROTECTED,
            source=SourceDomain.GMAIL,
            cloud_approved=False,
            scanned=True,
            scan_summary=scan_summary,
            metadata={"operation": operation_name}
        )
