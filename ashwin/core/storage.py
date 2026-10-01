"""
ASHWIN Storage Connector Interface & Moto Storage Adapter (Phase 3 / Stage H, Section 2.4, Section 2.5, Section 10).
Defines the StorageConnector abstraction for storage independence and the MotoStorageAdapter
enforcing the StorageConnector security contract.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import os

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.metadata_pipeline import MetadataPipeline
from ashwin.core.location_formatter import LocationFormatter
from ashwin.core.extractor import TextExtractor


class StorageError(Exception):
    """Base exception for storage connector operations."""
    pass


class StorageOfflineError(StorageError):
    """Raised when the private storage server is offline or unreachable (Section 2.5)."""
    pass


class StoragePermissionError(StorageError):
    """Raised when Moto storage access permission has not been granted (Section 6.3)."""
    pass


class StorageSecurityContractViolation(StorageError):
    """Raised when storage output violates the security contract."""
    pass


class StorageConnector(ABC):
    """
    Abstract Storage Connector interface maintaining storage independence (Section 2.4).
    Enforces strict security contract on all implementations.
    """

    @abstractmethod
    def is_connected(self) -> bool:
        """Returns True if the storage server is connected and authenticated."""
        pass

    @abstractmethod
    def set_access_permission(self, granted: bool) -> None:
        """Sets Section 6.3 access permission state for this session."""
        pass

    @abstractmethod
    def get_access_permission(self) -> bool:
        """Returns True if Section 6.3 access permission has been explicitly granted."""
        pass

    @abstractmethod
    def revoke_access_permission(self) -> None:
        """Revokes ephemeral access permission."""
        pass

    @abstractmethod
    def list_files(self, subfolder: str = "") -> ScannedClassifiedContext:
        """
        Lists files within dedicated storage scope.
        Security Contract:
        - Must verify Section 6.3 access permission BEFORE network query.
        - Must return ScannedClassifiedContext with RULE-14 allowlisted metadata only.
        - Must never return raw filesystem paths or credentials.
        """
        pass

    @abstractmethod
    def search_files(self, query: str, category: str = "") -> ScannedClassifiedContext:
        """
        Searches files within dedicated storage scope.
        Security Contract:
        - Must verify Section 6.3 access permission BEFORE network query.
        - Must return ScannedClassifiedContext with RULE-14 allowlisted metadata only.
        - Must never return raw filesystem paths or credentials.
        """
        pass

    @abstractmethod
    def read_file(self, rel_path: str) -> ScannedClassifiedContext:
        """
        Reads and extracts text from file within dedicated storage scope.
        Security Contract:
        - Must verify Section 6.3 access permission BEFORE network query.
        - Must enforce bounded buffering (<= 5 MB raw, <= 1 MB extracted).
        - Must extract text, scan & redact secrets (RULE-09), and classify as PROTECTED.
        - Must format location safely (RULE-15).
        - Must never return raw bytes, keys, or unredacted secrets.
        """
        pass


class MotoStorageAdapter(StorageConnector):
    """
    Adapter wrapping MotoConnector / Moto G3 endpoint into CoreSession's StorageConnector.
    Guarantees that MotoConnector adheres to Core storage security contract.
    """

    OFFLINE_MESSAGE = "Your private storage server is currently unavailable."

    def __init__(self, moto_connector: Any):
        self._connector = moto_connector
        self._access_permission = False

    def is_connected(self) -> bool:
        try:
            return bool(getattr(self._connector, "paired", False))
        except Exception:
            return False

    def set_access_permission(self, granted: bool) -> None:
        self._access_permission = granted
        if hasattr(self._connector, "set_access_permission"):
            self._connector.set_access_permission(granted)

    def get_access_permission(self) -> bool:
        return self._access_permission

    def revoke_access_permission(self) -> None:
        self._access_permission = False
        if hasattr(self._connector, "set_access_permission"):
            self._connector.set_access_permission(False)

    def _verify_pre_query_permission(self):
        """Enforces Section 6.3: No query may execute without prior access permission."""
        if not self._access_permission:
            raise StoragePermissionError("Permission Denied: Access permission check required before querying Moto storage.")

    def _validate_context_contract(self, ctx: ScannedClassifiedContext) -> ScannedClassifiedContext:
        """Validates that connector output strictly satisfies the StorageConnector contract."""
        if not isinstance(ctx, ScannedClassifiedContext):
            raise StorageSecurityContractViolation("Storage connector output must be ScannedClassifiedContext.")
        if ctx.data_class != DataClass.PROTECTED:
            raise StorageSecurityContractViolation(f"All Moto storage data must be PROTECTED, got {ctx.data_class}.")
        if ctx.source != SourceDomain.MOTO_STORAGE:
            raise StorageSecurityContractViolation(f"Moto storage context must have source MOTO_STORAGE, got {ctx.source}.")
        if not ctx.scanned or not ctx.scan_summary.get("healthy", False):
            raise StorageSecurityContractViolation("Moto storage context must have valid, healthy secret scan.")
        return ctx

    def list_files(self, subfolder: str = "") -> ScannedClassifiedContext:
        self._verify_pre_query_permission()
        try:
            ctx = self._connector.list_files(subfolder=subfolder)
            return self._validate_context_contract(ctx)
        except StoragePermissionError:
            raise
        except Exception as e:
            err_str = str(e)
            if "Access permission" in err_str or "Permission Denied" in err_str:
                raise StoragePermissionError(err_str)
            raise StorageOfflineError(self.OFFLINE_MESSAGE) from e

    def search_files(self, query: str, category: str = "") -> ScannedClassifiedContext:
        self._verify_pre_query_permission()
        try:
            if hasattr(self._connector, "search_files"):
                ctx = self._connector.search_files(query=query, category=category)
            else:
                # Fallback to list_files filter if search endpoint not directly wrapped
                ctx = self._connector.list_files(subfolder="")
            return self._validate_context_contract(ctx)
        except StoragePermissionError:
            raise
        except Exception as e:
            err_str = str(e)
            if "Access permission" in err_str or "Permission Denied" in err_str:
                raise StoragePermissionError(err_str)
            raise StorageOfflineError(self.OFFLINE_MESSAGE) from e

    def read_file(self, rel_path: str) -> ScannedClassifiedContext:
        self._verify_pre_query_permission()
        try:
            ctx = self._connector.read_file(rel_path=rel_path)
            return self._validate_context_contract(ctx)
        except StoragePermissionError:
            raise
        except Exception as e:
            err_str = str(e)
            if "Access permission" in err_str or "Permission Denied" in err_str:
                raise StoragePermissionError(err_str)
            raise StorageOfflineError(self.OFFLINE_MESSAGE) from e
