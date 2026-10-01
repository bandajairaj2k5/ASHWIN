"""
ASHWIN Permissions and Authorization Pipeline (Section 6).
Enforces source selection, capability authorization, permission classes, sensitive action confirmations,
and the untrusted content rule.
"""

from typing import Dict, Any, List, Optional, Set
from ashwin.core.models import PermissionClass, SourceDomain, SecurityViolation


class PermissionDeniedError(Exception):
    """Raised when an operation fails permission checks."""
    pass


class PermissionManager:
    """
    Implements Section 6 authorization pipeline, source management, and permission controls.
    """

    SENSITIVE_ACTIONS: Set[str] = {
        "send_email",
        "modify_github",
        "publish_linkedin",
        "modify_website",
        "delete_data",
        "upload_private_data",
        "cloud_processing_of_protected_data",
    }

    def __init__(self):
        self._approved_sources: Set[SourceDomain] = {SourceDomain.PHONE}
        self._approved_laptop_scopes: Set[str] = set()
        self._moto_access_granted: bool = False
        self._preferred_source: Optional[SourceDomain] = None

    def authorize_source(self, source: SourceDomain):
        self._approved_sources.add(source)

    def revoke_source(self, source: SourceDomain):
        self._approved_sources.discard(source)
        if source == SourceDomain.MOTO_STORAGE:
            self._moto_access_granted = False

    def set_moto_access(self, granted: bool):
        self._moto_access_granted = granted
        if granted:
            self._approved_sources.add(SourceDomain.MOTO_STORAGE)

    def is_moto_access_granted(self) -> bool:
        return self._moto_access_granted and (SourceDomain.MOTO_STORAGE in self._approved_sources)

    def add_laptop_scope(self, scope_path: str):
        # Normalize scope path
        normalized = scope_path.replace("\\", "/").rstrip("/").lower()
        self._approved_laptop_scopes.add(normalized)

    def remove_laptop_scope(self, scope_path: str):
        normalized = scope_path.replace("\\", "/").rstrip("/").lower()
        self._approved_laptop_scopes.discard(normalized)

    def is_laptop_scope_approved(self, path: str) -> bool:
        normalized = path.replace("\\", "/").rstrip("/").lower()
        for scope in self._approved_laptop_scopes:
            if normalized == scope or normalized.startswith(scope + "/"):
                return True
        return False

    def select_source(
        self,
        requested_domain: Optional[SourceDomain],
        user_choice: Optional[SourceDomain] = None
    ) -> SourceDomain:
        """
        Section 6.2 Source selection.
        """
        if requested_domain:
            if requested_domain not in self._approved_sources:
                raise PermissionDeniedError(f"Source domain {requested_domain.value} is not authorized.")
            return requested_domain

        if self._preferred_source and self._preferred_source in self._approved_sources:
            return self._preferred_source

        if user_choice:
            if user_choice not in self._approved_sources:
                raise PermissionDeniedError(f"Selected source {user_choice.value} is not authorized.")
            return user_choice

        raise PermissionDeniedError("Ambiguous source: User prompt required to select source.")

    def evaluate_tool_pipeline(
        self,
        tool_name: str,
        tool_class: PermissionClass,
        source: SourceDomain,
        target_path: Optional[str] = None,
        user_confirmed: bool = False,
        untrusted_content_instruction: bool = False
    ) -> bool:
        """
        Section 6.4 Authorization Pipeline & Section 6.7 Untrusted Content Rule.
        """
        # Section 6.7: Untrusted content can NEVER authorize actions or bypass rules
        if untrusted_content_instruction:
            raise SecurityViolation("Section 6.7 Violation: Untrusted content cannot grant permissions or authorize tools.")

        # Step 1: Source authorized?
        if source == SourceDomain.MOTO_STORAGE and not self.is_moto_access_granted():
            raise PermissionDeniedError("Moto storage access permission has not been granted by user.")

        if source not in self._approved_sources:
            raise PermissionDeniedError(f"Source {source.value} is not authorized.")

        # Step 2: Target valid inside scope?
        if source == SourceDomain.LAPTOP and target_path:
            if not self.is_laptop_scope_approved(target_path):
                raise PermissionDeniedError(f"Target path '{target_path}' is outside approved laptop scopes.")

        # Step 3: Class D or Sensitive actions require explicit user confirmation
        if tool_class == PermissionClass.CLASS_D or tool_name in self.SENSITIVE_ACTIONS:
            if not user_confirmed:
                raise PermissionDeniedError(f"Action '{tool_name}' requires explicit user confirmation.")

        return True
