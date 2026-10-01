"""
ASHWIN Online Connectors Base (Section 12).
Declares connector identity, supported operations, operation schemas, metadata allowlists,
permission requirements, and confirmation requirements.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set
from ashwin.core.models import DataClass, SourceDomain, ScannedClassifiedContext
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.metadata_pipeline import MetadataPipeline


class BaseConnector(ABC):
    """
    Abstract Base Class for Online Connectors (Section 12).
    """

    def __init__(self, source_domain: SourceDomain):
        self.source_domain = source_domain
        self.authenticated = False
        self.scanner = SecretScanner()
        self.metadata_pipeline = MetadataPipeline(scanner=self.scanner)
        self._credentials_token: Optional[str] = None

    def set_credentials(self, token: str):
        """Credentials stored securely in connector only, never passed to AI (Section 12)."""
        self._credentials_token = token
        self.authenticated = True

    @property
    @abstractmethod
    def declared_operations(self) -> Set[str]:
        pass

    @property
    @abstractmethod
    def metadata_allowlist(self) -> Set[str]:
        pass

    def invoke_operation(
        self,
        operation_name: str,
        params: Dict[str, Any],
        user_confirmed: bool = False
    ) -> ScannedClassifiedContext:
        if operation_name not in self.declared_operations:
            raise ValueError(f"Operation '{operation_name}' is not declared by connector {self.source_domain.value}.")
        if not self.authenticated:
            raise PermissionError(f"Connector {self.source_domain.value} is not authenticated.")
        
        return self._execute_operation(operation_name, params, user_confirmed)

    @abstractmethod
    def _execute_operation(
        self,
        operation_name: str,
        params: Dict[str, Any],
        user_confirmed: bool
    ) -> ScannedClassifiedContext:
        pass
