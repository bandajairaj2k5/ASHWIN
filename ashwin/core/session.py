"""
ASHWIN Core Session Management (Phase 3 / Stage A through Stage I, Phase 4, Section 2, Section 5, Section 6, Section 8, Section 10, Section 12).
Manages Core execution lifecycle, session isolation, component binding, storage connector integration,
laptop connector integration, and fail-closed state.
"""

import time
import uuid
from typing import Dict, Any, Optional, Callable

from ashwin.core.credentials import CredentialStore
from ashwin.core.endpoint_config import EndpointConfig
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.audit import AuditLogger
from ashwin.core.memory import EphemeralMemoryStore
from ashwin.core.classifier import InputClassifier
from ashwin.core.router import AIRouter
from ashwin.core.storage import StorageConnector, StorageOfflineError, StoragePermissionError, MotoStorageAdapter
from ashwin.core.laptop_connector import LaptopConnector, LaptopOfflineError, LaptopPermissionError
from ashwin.core.models import DataClass, SourceDomain, SecurityViolation, ScannedClassifiedContext
from ashwin.core.consent import ConsentCoordinator, ConsentMetadata, CloudConsentToken


class CoreSessionError(Exception):
    """Raised for session lifecycle, initialization, or health check failures."""
    pass


class CoreSession:
    """
    Core Session Coordinator maintaining component bindings, storage operations,
    laptop endpoint operations, turn execution, and session lifecycle.
    """

    def __init__(
        self,
        credential_store: Optional[CredentialStore] = None,
        scanner: Optional[SecretScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        memory_store: Optional[EphemeralMemoryStore] = None,
        classifier: Optional[InputClassifier] = None,
        router: Optional[AIRouter] = None,
        storage_connector: Optional[StorageConnector] = None,
        laptop_connector: Optional[LaptopConnector] = None,
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
        self.storage_connector = storage_connector
        self.laptop_connector = laptop_connector

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

    def set_storage_connector(self, connector: Optional[StorageConnector]):
        """Binds or updates the pluggable storage connector."""
        self.storage_connector = connector

    def set_laptop_connector(self, connector: Optional[LaptopConnector]):
        """Binds or updates the laptop connector."""
        self.laptop_connector = connector

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

    def execute_storage_turn(
        self,
        command_text: str,
        operation: str,
        target_path: str = "",
        permission_prompt_callback: Optional[Callable[[str], bool]] = None,
        consent_coordinator: Optional[ConsentCoordinator] = None,
        direct_consent_token: Optional[CloudConsentToken] = None
    ) -> Dict[str, Any]:
        """
        Executes a conversational turn involving Moto Storage:
        1. Classifies and records the User's command context (SourceDomain.PHONE).
        2. Prompts Section 6.3 Access Permission BEFORE any storage query.
        3. If denied, halts cleanly without network call.
        4. If granted, executes storage query through StorageConnector.
        5. Validates bounded, extracted, scanned, and classified storage context.
        6. Inserts strictly ScannedClassifiedContext into EphemeralMemoryStore.
        7. Delivers through AIRouter (sole model boundary) with CloudConsentToken if needed.
        8. Handles offline/unreachable storage cleanly (Section 2.5).
        """
        if not self.is_active:
            raise SecurityViolation("CoreSession is inactive. Ingress rejected.")

        # Step 1: Ingest User Command as distinct PHONE context
        user_cmd_context = self.classifier.process_user_input(
            raw_text=command_text,
            source=SourceDomain.PHONE,
            is_stt=False
        )
        self.memory_store.add_context(user_cmd_context)

        if not self.storage_connector:
            return {
                "status": "UNAVAILABLE",
                "message": "Your private storage server is currently unavailable.",
                "reason": "No storage connector configured."
            }

        # Step 2: Access Permission Check (Section 6.3) BEFORE any network/metadata query
        if not self.storage_connector.get_access_permission():
            prompt_text = "Your private Moto storage requires permission. May I access it?"
            granted = False
            if permission_prompt_callback is not None:
                granted = permission_prompt_callback(prompt_text)
            
            if not granted:
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="MOTO_ACCESS_PERMISSION_DENIED",
                        status="DENIED",
                        details={"operation": operation, "target": target_path}
                    )
                return {
                    "status": "DENIED",
                    "message": "Moto storage access permission was denied. No storage data was retrieved.",
                    "reason": "Access permission denied by user."
                }
            
            self.storage_connector.set_access_permission(True)
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="MOTO_ACCESS_PERMISSION_GRANTED",
                    status="GRANTED",
                    details={"operation": operation, "target": target_path}
                )

        # Step 3: Execute Storage Query over connector
        try:
            if operation == "list":
                storage_context = self.storage_connector.list_files(subfolder=target_path)
            elif operation == "search":
                storage_context = self.storage_connector.search_files(query=target_path)
            elif operation == "read":
                storage_context = self.storage_connector.read_file(rel_path=target_path)
            else:
                return {
                    "status": "ERROR",
                    "message": f"Unsupported storage operation: {operation}"
                }
        except StorageOfflineError as e:
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="STORAGE_OFFLINE",
                    status="OFFLINE",
                    details={"message": str(e)}
                )
            return {
                "status": "OFFLINE",
                "message": str(e)
            }
        except StoragePermissionError as e:
            return {
                "status": "DENIED",
                "message": str(e)
            }
        except Exception as e:
            return {
                "status": "OFFLINE",
                "message": "Your private storage server is currently unavailable."
            }

        # Step 4: Memory insertion of verified ScannedClassifiedContext (RULE-04, RULE-05)
        self.memory_store.add_context(storage_context)

        # Step 5: Deliver storage context through AIRouter (sole boundary)
        router_result = self.router.process_context(
            context=storage_context,
            consent_token=direct_consent_token
        )

        if router_result.get("status") == "SUCCESS":
            return router_result

        # Step 6: Interactive Cloud Consent resolution if local AI is unavailable
        if router_result.get("user_prompt_required", False) and consent_coordinator is not None:
            metadata = ConsentMetadata(
                source_domain=storage_context.source,
                data_class=storage_context.data_class,
                target_provider=router_result.get("target_provider", "CloudAI"),
                rationale=(
                    f"Local AI is unavailable. Processing private Moto storage file/metadata with "
                    f"Cloud AI requires your explicit consent."
                )
            )
            consent_token = consent_coordinator.request_consent(metadata)
            if consent_token is not None:
                second_result = self.router.process_context(
                    context=storage_context,
                    consent_token=consent_token
                )
                return second_result
            else:
                return {
                    "status": "DENIED",
                    "reason": "Cloud AI consent was denied by user. Private storage data was not transmitted.",
                    "message": "Cloud AI consent was denied by user. Private storage data was not transmitted."
                }

        return router_result

    def execute_laptop_turn(
        self,
        command_text: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        permission_prompt_callback: Optional[Callable[[str], bool]] = None,
        consent_coordinator: Optional[ConsentCoordinator] = None,
        direct_consent_token: Optional[CloudConsentToken] = None
    ) -> Dict[str, Any]:
        """
        Executes a turn involving the Windows Laptop Endpoint (Phase 4):
        1. Ingests User command as distinct PHONE context.
        2. Enforces Section 6.3 Laptop Access Permission BEFORE any tool invocation.
        3. Executes requested tool through LaptopConnector.
        4. If tool returns ScannedClassifiedContext (read_document_text, system info):
           - Validates ScannedClassifiedContext (PROTECTED, SourceDomain.LAPTOP).
           - Inserts into EphemeralMemoryStore.
           - Delivers via AIRouter (sole boundary) with optional CloudConsentToken.
        5. If tool returns status/message (open_folder, view_document, open_allowed_app):
           - Verifies zero document content leakage.
           - Logs audit event and returns status.
        6. Handles offline/unreachable laptop cleanly without breaking Core.
        """
        if not self.is_active:
            raise SecurityViolation("CoreSession is inactive. Ingress rejected.")

        tool_args = tool_args or {}

        # Step 1: Ingest User Command as PHONE context
        user_cmd_context = self.classifier.process_user_input(
            raw_text=command_text,
            source=SourceDomain.PHONE,
            is_stt=False
        )
        self.memory_store.add_context(user_cmd_context)

        if not self.laptop_connector:
            return {
                "status": "UNAVAILABLE",
                "message": "Your Windows laptop endpoint is currently unavailable.",
                "reason": "No laptop connector configured."
            }

        # Step 2: Access Permission Check BEFORE any endpoint query
        if not self.laptop_connector.get_access_permission():
            prompt_text = "Your Windows laptop requires permission. May I access it?"
            granted = False
            if permission_prompt_callback is not None:
                granted = permission_prompt_callback(prompt_text)

            if not granted:
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="LAPTOP_ACCESS_PERMISSION_DENIED",
                        status="DENIED",
                        details={"tool": tool_name, "args": tool_args}
                    )
                return {
                    "status": "DENIED",
                    "message": "Laptop access permission was denied. No laptop data was retrieved.",
                    "reason": "Access permission denied by user."
                }

            self.laptop_connector.set_access_permission(True)
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="LAPTOP_ACCESS_PERMISSION_GRANTED",
                    status="GRANTED",
                    details={"tool": tool_name, "args": tool_args}
                )

        # Step 3: Execute tool over connector
        try:
            if tool_name == "find_file":
                results = self.laptop_connector.find_file(query=tool_args.get("query", ""))
                return {"status": "SUCCESS", "results": results, "content_returned_to_model": False}

            elif tool_name == "find_folder":
                results = self.laptop_connector.find_folder(query=tool_args.get("query", ""))
                return {"status": "SUCCESS", "results": results, "content_returned_to_model": False}

            elif tool_name == "list_folder":
                results = self.laptop_connector.list_folder(folder_id=tool_args.get("folder_id", ""))
                return {"status": "SUCCESS", "results": results, "content_returned_to_model": False}

            elif tool_name == "open_folder":
                msg = self.laptop_connector.open_folder(folder_id=tool_args.get("folder_id", ""))
                return {"status": "SUCCESS", "message": msg, "content_returned_to_model": False}

            elif tool_name == "view_document":
                msg = self.laptop_connector.view_document(file_id=tool_args.get("file_id", ""))
                return {"status": "SUCCESS", "message": msg, "content_returned_to_model": False}

            elif tool_name == "open_allowed_app":
                msg = self.laptop_connector.open_allowed_app(
                    app_id=tool_args.get("app_id", ""),
                    user_confirmed=tool_args.get("user_confirmed", False)
                )
                return {"status": "SUCCESS", "message": msg, "content_returned_to_model": False}

            elif tool_name == "read_document_text":
                ctx = self.laptop_connector.read_document_text(file_id=tool_args.get("file_id", ""))

            elif tool_name == "get_open_apps":
                ctx = self.laptop_connector.get_open_apps()

            elif tool_name == "get_processes":
                ctx = self.laptop_connector.get_processes()

            elif tool_name == "get_connected_devices":
                ctx = self.laptop_connector.get_connected_devices()

            else:
                return {
                    "status": "ERROR",
                    "message": f"Unsupported laptop tool: {tool_name}"
                }

        except LaptopOfflineError as e:
            if self.audit_logger:
                self.audit_logger.log(
                    event_type="LAPTOP_OFFLINE",
                    status="OFFLINE",
                    details={"message": str(e)}
                )
            return {"status": "OFFLINE", "message": str(e)}
        except LaptopPermissionError as e:
            return {"status": "DENIED", "message": str(e)}
        except Exception as e:
            return {"status": "OFFLINE", "message": "Your Windows laptop endpoint is currently unavailable."}

        # Step 4: For tools returning ScannedClassifiedContext, deliver through Router
        self.memory_store.add_context(ctx)

        router_result = self.router.process_context(
            context=ctx,
            consent_token=direct_consent_token
        )

        if router_result.get("status") == "SUCCESS":
            return router_result

        # Step 5: Cloud consent resolution if local AI is unavailable
        if router_result.get("user_prompt_required", False) and consent_coordinator is not None:
            metadata = ConsentMetadata(
                source_domain=ctx.source,
                data_class=ctx.data_class,
                target_provider=router_result.get("target_provider", "CloudAI"),
                rationale=(
                    f"Local AI is unavailable. Processing private laptop content with "
                    f"Cloud AI requires your explicit consent."
                )
            )
            consent_token = consent_coordinator.request_consent(metadata)
            if consent_token is not None:
                second_result = self.router.process_context(
                    context=ctx,
                    consent_token=consent_token
                )
                return second_result
            else:
                return {
                    "status": "DENIED",
                    "reason": "Cloud AI consent was denied by user. Private laptop data was not transmitted.",
                    "message": "Cloud AI consent was denied by user. Private laptop data was not transmitted."
                }

        return router_result

    def reset_session(self):
        """
        Resets ephemeral session state while preserving persistent credentials in CredentialStore.
        Revokes any active ephemeral storage and laptop access permissions.
        """
        old_id = self.session_id
        self.session_id = str(uuid.uuid4())
        self.created_at = time.time()
        self.is_active = True
        self.memory_store.clear()
        if self.storage_connector:
            self.storage_connector.revoke_access_permission()
        if self.laptop_connector:
            self.laptop_connector.revoke_access_permission()
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
        if self.storage_connector:
            self.storage_connector.revoke_access_permission()
        if self.laptop_connector:
            self.laptop_connector.revoke_access_permission()
        if self.audit_logger:
            self.audit_logger.log(
                event_type="SESSION_TERMINATED",
                status="SUCCESS",
                details={"session_id": self.session_id}
            )
