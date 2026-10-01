"""
ASHWIN Laptop Connector & Security Interface (Phase 4, Section 8, Section 10, RULE-06, RULE-07, RULE-08).
Manages secure communication between CoreSession and the Windows Laptop Endpoint Agent.
Enforces pre-query access permissions, StorageConnector security contracts, context typing, and fail-closed behavior.
"""

from typing import Optional, Dict, Any, List
import os

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.laptop_agent.agent import WindowsLaptopAgent, AgentSecurityError
try:
    from ashwin.laptop_agent.transport import LaptopEndpointClient, LaptopCryptoManager
except ImportError:
    LaptopEndpointClient = None


class LaptopError(Exception):
    """Base exception for laptop connector operations."""
    pass


class LaptopOfflineError(LaptopError):
    """Raised when the Windows laptop endpoint is offline or unreachable."""
    pass


class LaptopPermissionError(LaptopError):
    """Raised when laptop access permission has not been granted."""
    pass


class LaptopSecurityContractViolation(LaptopError):
    """Raised when laptop agent output violates the security contract."""
    pass


class LaptopConnector:
    """
    Core-side connector managing communication with the Windows Laptop Agent.
    Strictly owned and orchestrated by CoreSession. VoiceSubsystem, AIRouter, and providers
    must never access LaptopConnector directly.
    """

    OFFLINE_MESSAGE = "Your Windows laptop endpoint is currently unavailable."

    def __init__(
        self,
        laptop_agent: Optional[WindowsLaptopAgent] = None,
        client: Optional[Any] = None
    ):
        self._agent = laptop_agent
        self._client = client
        self._access_permission = False

    def set_agent(self, agent: Optional[WindowsLaptopAgent]):
        """Binds or updates the Windows laptop agent instance."""
        self._agent = agent

    def set_client(self, client: Optional[Any]):
        """Binds or updates the live mTLS endpoint client."""
        self._client = client

    def is_connected(self) -> bool:
        """Returns True if the laptop agent is present and paired."""
        if self._client:
            return bool(getattr(self._client.crypto_mgr, "paired", False))
        if self._agent:
            return bool(getattr(self._agent, "paired", False))
        return False

    def set_access_permission(self, granted: bool) -> None:
        """Sets Section 6.3 access permission state for this session."""
        self._access_permission = bool(granted)

    def get_access_permission(self) -> bool:
        """Returns True if Section 6.3 access permission has been explicitly granted."""
        return self._access_permission

    def revoke_access_permission(self) -> None:
        """Revokes ephemeral access permission."""
        self._access_permission = False

    def _verify_pre_query_permission(self):
        """Enforces Section 6.3: No query may execute without prior access permission."""
        if not self._access_permission:
            raise LaptopPermissionError("Permission Denied: Access permission check required before querying laptop.")

    def _ensure_connected(self):
        """Ensures the laptop endpoint is connected and healthy."""
        if not self._agent or not self._agent.paired:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE)

    def _validate_context_contract(self, ctx: ScannedClassifiedContext) -> ScannedClassifiedContext:
        """Validates that connector output strictly satisfies the Core security contract."""
        if not isinstance(ctx, ScannedClassifiedContext):
            raise LaptopSecurityContractViolation("Laptop connector output must be ScannedClassifiedContext.")
        if ctx.data_class != DataClass.PROTECTED:
            raise LaptopSecurityContractViolation(f"All laptop data must be PROTECTED, got {ctx.data_class}.")
        if ctx.source != SourceDomain.LAPTOP:
            raise LaptopSecurityContractViolation(f"Laptop context must have source LAPTOP, got {ctx.source}.")
        if not ctx.scanned or not ctx.scan_summary.get("healthy", False):
            raise LaptopSecurityContractViolation("Laptop context must have valid, healthy secret scan.")
        return ctx

    # ==================== TEN APPROVED TOOLS ====================

    def find_file(self, query: str) -> List[Dict[str, Any]]:
        """Tool 1: find_file"""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.find_file(query)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def find_folder(self, query: str) -> List[Dict[str, Any]]:
        """Tool 2: find_folder"""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.find_folder(query)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def list_folder(self, folder_id: str) -> List[Dict[str, Any]]:
        """Tool 3: list_folder"""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.list_folder(folder_id)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def open_folder(self, folder_id: str) -> str:
        """
        Tool 4: open_folder. Returns confirmation message.
        Zero document or folder content is returned to Core/model.
        """
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.open_folder(folder_id)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def view_document(self, file_id: str) -> str:
        """
        Tool 5: view_document. Returns confirmation message.
        Zero document content is returned to Core/model.
        """
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.view_document(file_id)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def read_document_text(self, file_id: str) -> ScannedClassifiedContext:
        """
        Tool 6: read_document_text. Class C.
        The ONLY V1 tool that returns document text to Core/model.
        """
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            ctx = self._agent.read_document_text(file_id)
            return self._validate_context_contract(ctx)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def open_allowed_app(self, app_id: str, user_confirmed: bool = False) -> str:
        """Tool 7: open_allowed_app. Class D tool."""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            return self._agent.open_allowed_app(app_id, user_confirmed=user_confirmed)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def get_open_apps(self) -> ScannedClassifiedContext:
        """Tool 8: get_open_apps. Class A tool."""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            ctx = self._agent.get_open_apps()
            return self._validate_context_contract(ctx)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def get_processes(self) -> ScannedClassifiedContext:
        """Tool 9: get_processes. Class A tool."""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            ctx = self._agent.get_processes()
            return self._validate_context_contract(ctx)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e

    def get_connected_devices(self) -> ScannedClassifiedContext:
        """Tool 10: get_connected_devices. Class A tool."""
        self._verify_pre_query_permission()
        self._ensure_connected()
        try:
            ctx = self._agent.get_connected_devices()
            return self._validate_context_contract(ctx)
        except AgentSecurityError as e:
            raise LaptopError(str(e)) from e
        except Exception as e:
            raise LaptopOfflineError(self.OFFLINE_MESSAGE) from e
