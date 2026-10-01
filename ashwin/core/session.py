"""
ASHWIN Core Session Management (Phase 3 / Stage A, Section 2, Section 5, Section 12).
Manages Core execution lifecycle, session isolation, component binding, and fail-closed state.
"""

import time
import uuid
from typing import Dict, Any, Optional

from ashwin.core.credentials import CredentialStore
from ashwin.core.endpoint_config import EndpointConfig
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.audit import AuditLogger
from ashwin.core.memory import EphemeralMemoryStore


class CoreSessionError(Exception):
    """Raised for session lifecycle, initialization, or health check failures."""
    pass


class CoreSession:
    """
    Core Session Coordinator maintaining component bindings and session lifecycle.
    """

    def __init__(
        self,
        credential_store: Optional[CredentialStore] = None,
        scanner: Optional[SecretScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        memory_store: Optional[EphemeralMemoryStore] = None
    ):
        self.session_id = str(uuid.uuid4())
        self.created_at = time.time()
        self.is_active = True

        self.credential_store = credential_store or CredentialStore()
        self.scanner = scanner or SecretScanner()
        self.audit_logger = audit_logger or AuditLogger()
        self.memory_store = memory_store or EphemeralMemoryStore(scanner=self.scanner)

        # Fail-closed health check at initialization
        self._verify_health()

        if self.audit_logger:
            self.audit_logger.log(
                event_type="SESSION_START",
                status="SUCCESS",
                details={"session_id": self.session_id, "timestamp": self.created_at}
            )

    def _verify_health(self):
        """Verifies that all bound security components are healthy."""
        if not self.scanner or not self.scanner.is_healthy():
            self.is_active = False
            raise CoreSessionError("CoreSession initialization failed: SecretScanner is unhealthy.")

    def is_healthy(self) -> bool:
        """Returns True if the session is active and all bound security components are operational."""
        return self.is_active and self.scanner is not None and self.scanner.is_healthy()

    def reset_session(self):
        """
        Resets ephemeral session state while preserving persistent credentials in CredentialStore.
        """
        old_id = self.session_id
        self.session_id = str(uuid.uuid4())
        self.created_at = time.time()
        self.is_active = True
        self.memory_store.clear()
        self._verify_health()

        if self.audit_logger:
            self.audit_logger.log(
                event_type="SESSION_RESET",
                status="SUCCESS",
                details={"previous_session_id": old_id, "new_session_id": self.session_id}
            )

    def terminate_session(self):
        """Terminates active session and prevents further operations."""
        self.is_active = False
        self.memory_store.clear()
        if self.audit_logger:
            self.audit_logger.log(
                event_type="SESSION_TERMINATED",
                status="SUCCESS",
                details={"session_id": self.session_id}
            )
