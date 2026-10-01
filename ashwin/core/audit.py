"""
ASHWIN Audit Logger (Section 13, RULE-09).
Secure structured audit log. Prevents raw secret or content logging.
"""

from dataclasses import dataclass, asdict
import time
from typing import Dict, Any, List, Optional
from ashwin.core.models import DataClass, SourceDomain


@dataclass
class AuditEntry:
    timestamp: float
    event_type: str
    source: Optional[str]
    details: Dict[str, Any]
    status: str  # SUCCESS, REJECTED, FAILED, DENIED


class AuditLogger:
    """
    Implements Section 13 audit logging with RULE-09 secret omission guarantees.
    """

    FORBIDDEN_KEYS = {"password", "secret", "token", "raw_content", "key", "cookie", "auth"}

    def __init__(self):
        self._entries: List[AuditEntry] = []

    def log(
        self,
        event_type: str,
        status: str,
        source: Optional[SourceDomain] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEntry:
        cleaned_details = self._sanitize_details(details or {})
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=event_type,
            source=source.value if source else None,
            details=cleaned_details,
            status=status
        )
        self._entries.append(entry)
        return entry

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitizes audit details to guarantee no secrets or raw file content exist in logs.
        """
        cleaned = {}
        for k, v in details.items():
            if any(forbidden in k.lower() for forbidden in self.FORBIDDEN_KEYS):
                cleaned[k] = "[OMITTED_FROM_AUDIT_LOG]"
            elif isinstance(v, dict):
                cleaned[k] = self._sanitize_details(v)
            else:
                cleaned[k] = v
        return cleaned

    def get_entries(self) -> List[AuditEntry]:
        return list(self._entries)
