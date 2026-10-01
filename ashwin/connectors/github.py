"""
ASHWIN GitHub Connector (Section 12, Section 6.6).
"""

from typing import Dict, Any, Set
from ashwin.core.models import DataClass, SourceDomain, ScannedClassifiedContext, SecurityViolation
from ashwin.connectors.base import BaseConnector


class GitHubConnector(BaseConnector):

    def __init__(self):
        super().__init__(SourceDomain.GITHUB)

    @property
    def declared_operations(self) -> Set[str]:
        return {"read_repository", "read_issues", "modify_repository"}

    @property
    def metadata_allowlist(self) -> Set[str]:
        return {"repo_name", "issue_id", "title"}

    def _execute_operation(
        self,
        operation_name: str,
        params: Dict[str, Any],
        user_confirmed: bool
    ) -> ScannedClassifiedContext:
        if operation_name == "modify_repository":
            # Section 6.6: Sensitive action requires explicit confirmation
            if not user_confirmed:
                raise SecurityViolation("Section 6.6 Violation: modify_repository requires explicit user confirmation.")
            content = f"GitHub repository modified: {params.get('action')} on {params.get('repo')}"
        else:
            content = f"GitHub read content for {params.get('repo')}"

        redacted_text, scan_summary, _ = self.scanner.scan_and_redact(content)

        return ScannedClassifiedContext(
            content=redacted_text,
            data_class=DataClass.PROTECTED,
            source=SourceDomain.GITHUB,
            cloud_approved=False,
            scanned=True,
            scan_summary=scan_summary,
            metadata={"operation": operation_name}
        )
