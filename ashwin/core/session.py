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
from ashwin.core.classifier import InputClassifier
from ashwin.core.router import AIRouter


from ashwin.core.models import DataClass, SourceDomain, SecurityViolation
from ashwin.core.consent import ConsentCoordinator, ConsentMetadata, CloudConsentToken


class CoreSessionError(Exception):
    """Raised for session lifecycle, initialization, or health check failures."""
    pass


class CoreSession:
    """
    Core Session Coordinator maintaining component bindings, turn execution, and session lifecycle.
    """

    def __init__(
        self,
        credential_store: Optional[CredentialStore] = None,
        scanner: Optional[SecretScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        memory_store: Optional[EphemeralMemoryStore] = None,
        classifier: Optional[InputClassifier] = None,
        router: Optional[AIRouter] = None,
    ):
        self.session_id = str(uuid.uuid4())
        self.created_at = time.time()
        self.is_active = True

        self.credential_store = credential_store or CredentialStore()
        self.scanner = scanner or SecretScanner()
        self.audit_logger = audit_logger or AuditLogger()
        self.memory_store = memory_store or EphemeralMemoryStore(scanner=self.scanner)
        self.classifier = classifier or InputClassifier(scanner=self.scanner)
        self.router = router or AIRouter()

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

    def execute_turn(
        self,
        raw_text: str,
        source: SourceDomain = SourceDomain.PHONE,
        is_stt: bool = False,
        consent_coordinator: Optional[ConsentCoordinator] = None,
        direct_consent_token: Optional[CloudConsentToken] = None
    ) -> Dict[str, Any]:
        """
        Executes a complete turn through the security pipeline:
        1. InputClassifier & SecretScanner (Assigns PROTECTED by default, redacts credentials).
        2. Early hard fail-closed for HIGHLY_PROTECTED data (RULE-03).
        3. Ephemeral RAM memory insertion.
        4. AIRouter model delivery (Sole boundary, LocalAI by default).
        5. Interactive Cloud Consent resolution via ConsentCoordinator (Minimal metadata only, Section 4.5).
        """
        if not self.is_active:
            raise SecurityViolation("CoreSession is inactive. Ingress rejected.")

        # Step 1: Input Classification & Secret Scanning
        classified_context = self.classifier.process_user_input(
            raw_text=raw_text,
            source=source,
            is_stt=is_stt
        )

        # Step 2: Early Hard Fail-Closed for HIGHLY_PROTECTED (RULE-03)
        if classified_context.data_class == DataClass.HIGHLY_PROTECTED:
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="HIGHLY_PROTECTED_INGRESS_BLOCKED",
                    status="BLOCKED",
                    details={"source": source.value, "session_id": self.session_id}
                )
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter memory or model context.")

        # Step 3: Ephemeral RAM memory store insertion
        self.memory_store.add_context(classified_context)

        # Step 4: First AIRouter execution attempt (sole model-delivery boundary)
        router_result = self.router.process_context(
            context=classified_context,
            consent_token=direct_consent_token
        )

        if router_result.get("status") == "SUCCESS":
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="MODEL_DELIVERY_SUCCESS",
                    status="SUCCESS",
                    details={
                        "provider": router_result.get("provider_used"),
                        "is_local": router_result.get("is_local"),
                        "data_class": classified_context.data_class.value
                    }
                )
            return router_result

        # Step 5: Interactive Cloud Consent resolution if local AI is unavailable
        if router_result.get("user_prompt_required", False) and consent_coordinator is not None:
            metadata = ConsentMetadata(
                source_domain=classified_context.source,
                data_class=classified_context.data_class,
                target_provider=router_result.get("target_provider", "CloudAI"),
                rationale=(
                    f"Local AI is unavailable. Sending {classified_context.data_class.value} data "
                    f"from {classified_context.source.value} to Cloud AI requires your explicit consent."
                )
            )
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="CLOUD_CONSENT_REQUEST",
                    status="PROMPTED",
                    details=metadata.to_dict()
                )

            consent_token = consent_coordinator.request_consent(metadata)

            if consent_token is not None:
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="CLOUD_CONSENT_GRANTED",
                        status="GRANTED_ONCE",
                        details={"request_id": metadata.request_id, "token_id": consent_token.token_id}
                    )
                # Second Router attempt with valid structured ephemeral token
                second_result = self.router.process_context(
                    context=classified_context,
                    consent_token=consent_token
                )
                if second_result.get("status") == "SUCCESS" and self.audit_logger:
                    self.audit_logger.log(
                        event_type="MODEL_DELIVERY_SUCCESS",
                        status="SUCCESS",
                        details={
                            "provider": second_result.get("provider_used"),
                            "is_local": second_result.get("is_local"),
                            "data_class": classified_context.data_class.value
                        }
                    )
                return second_result
            else:
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="CLOUD_CONSENT_DENIED",
                        status="DENIED_BY_USER",
                        details={"request_id": metadata.request_id}
                    )
                return {
                    "status": "DENIED",
                    "reason": "Cloud AI consent was denied by user. Private data was not transmitted.",
                    "user_prompt_required": False,
                    "data_class": classified_context.data_class.value,
                    "source": classified_context.source.value,
                    "message": "Cloud AI consent was denied by user. Private data was not transmitted."
                }

        return router_result

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
