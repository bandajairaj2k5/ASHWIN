"""
ASHWIN Core Models - Data Classifications, Sources, and Gate Contracts.
ASHWIN-SPEC v1.0.1
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Optional, Set
import time


class DataClass(Enum):
    PUBLIC = "PUBLIC"
    PERSONAL = "PERSONAL"
    PROTECTED = "PROTECTED"
    HIGHLY_PROTECTED = "HIGHLY_PROTECTED"


class SourceDomain(Enum):
    PHONE = "PHONE"
    MOTO_STORAGE = "MOTO_STORAGE"
    LAPTOP = "LAPTOP"
    GMAIL = "GMAIL"
    CALENDAR = "CALENDAR"
    GITHUB = "GITHUB"
    LINKEDIN = "LINKEDIN"
    WEB = "WEB"


class PermissionClass(Enum):
    CLASS_A = "CLASS_A"  # System info (get_open_apps, get_processes, get_connected_devices)
    CLASS_B = "CLASS_B"  # Scoped discovery (find_file, find_folder, list_folder)
    CLASS_C = "CLASS_C"  # Open / view (open_folder, view_document, read_document_text)
    CLASS_D = "CLASS_D"  # Application launch (open_allowed_app)


class ConnectionState(Enum):
    UNPAIRED = "UNPAIRED"
    OFFLINE = "OFFLINE"
    CONNECTED = "CONNECTED"


class RouterGateError(Exception):
    """Raised when context fails Router-ingress gate validation (RULE-04, RULE-05)."""
    pass


class SecurityViolation(Exception):
    """Raised when security invariants (e.g. RULE-03) are violated."""
    pass


@dataclass(frozen=True)
class ScannedClassifiedContext:
    """
    Scanned and classified context wrapper required by the AI Router (RULE-04).
    Enforces that no context reaches an AI model without passing through scanning,
    classification, and validation.
    """
    content: str
    data_class: DataClass
    source: SourceDomain
    cloud_approved: bool = False
    scanned: bool = False
    scan_summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        # RULE-04: Any context object lacking a valid scanned-and-classified state is rejected
        if not self.scanned:
            raise RouterGateError("Context rejected: Object has not passed secret scanning.")
        if not isinstance(self.data_class, DataClass):
            raise RouterGateError("Context rejected: Invalid or missing data classification.")
        if not self.scan_summary.get("healthy", False):
            raise RouterGateError("Context rejected: Secret scanner health check failed.")
        # RULE-03: HIGHLY PROTECTED data never enters model context
        if self.data_class == DataClass.HIGHLY_PROTECTED:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")
