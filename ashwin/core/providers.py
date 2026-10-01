"""
ASHWIN AI Provider Interfaces and Replaceable Cloud AI Abstraction (Phase 3 / Stage D).
Defines provider contracts, LocalAI runtime abstraction, BaseCloudAIProvider, and GeminiCloudProvider.

Note:
GeminiCloudProvider is a provider abstraction / architectural foundation for Phase 3.
It enforces strict CredentialStore credential binding and router authorization boundaries,
and does not yet execute live external network HTTP requests.
"""

from typing import Optional, Protocol, Dict, Any
from abc import ABC, abstractmethod
from ashwin.core.credentials import CredentialStore


class ProviderError(Exception):
    """Base exception for AI provider operations."""
    pass


class ProviderCredentialError(ProviderError):
    """Raised when required credentials for a provider are missing or invalid."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when an AI provider is unreachable or temporarily unavailable."""
    pass


class AIProvider(Protocol):
    name: str
    is_local: bool

    def generate_response(self, prompt: str) -> str:
        ...


class LocalAIProvider:
    """
    On-device Local AI Provider abstraction.
    Default destination for PROTECTED data.
    """
    name: str = "LocalAI"
    is_local: bool = True

    def __init__(self, model_identifier: str = "local-default"):
        self.model_identifier = model_identifier

    def generate_response(self, prompt: str) -> str:
        # Runtime/model-agnostic on-device inference placeholder / execution
        return f"[LocalAI Response ({self.model_identifier})]: Processed prompt: '{prompt[:50]}...'"


class BaseCloudAIProvider(ABC):
    """
    Abstract base class for all Cloud AI Providers.
    Ensures provider replaceability and credential retrieval through CredentialStore.
    """
    name: str = "CloudAI"
    is_local: bool = False

    def __init__(
        self,
        credential_store: Optional[CredentialStore] = None,
        model_identifier: str = "cloud-default"
    ):
        self.credential_store = credential_store
        self.model_identifier = model_identifier

    @abstractmethod
    def generate_response(self, prompt: str) -> str:
        """Executes cloud model generation after router authorization."""
        pass


class GeminiCloudProvider(BaseCloudAIProvider):
    """
    Gemini Cloud AI Provider (first concrete CloudAIProvider implementation).
    Retrieves API key strictly and exclusively from CredentialStore.
    No direct constructor credential injection, plaintext fallback, environment fallback, or hardcoding.
    """
    name: str = "GeminiCloudAI"
    is_local: bool = False

    def __init__(
        self,
        credential_store: Optional[CredentialStore] = None,
        model_identifier: str = "gemini-1.5-flash"
    ):
        super().__init__(credential_store=credential_store, model_identifier=model_identifier)

    def _get_api_key(self) -> str:
        if not self.credential_store:
            raise ProviderCredentialError(
                "CredentialStore is not configured for GeminiCloudProvider. Cloud AI credentials must be loaded via CredentialStore."
            )
        key = self.credential_store.get_cloud_api_key()
        if not key or not key.strip():
            raise ProviderCredentialError(
                "Gemini API key is missing in CredentialStore. Cloud credentials must be provisioned before invoking Cloud AI."
            )
        return key.strip()

    def generate_response(self, prompt: str) -> str:
        """
        Generates response using Gemini API key from CredentialStore.
        Ensures credentials are not logged or embedded in prompt/output.
        """
        api_key = self._get_api_key()
        if not api_key:
            raise ProviderCredentialError("Gemini API key is blank.")

        return f"[GeminiCloudAI Response ({self.model_identifier})]: Safely processed authorized cloud prompt: '{prompt[:50]}...'"


class CloudAIProvider(BaseCloudAIProvider):
    """
    Generic Cloud AI Provider implementation.
    """
    name: str = "CloudAI"
    is_local: bool = False

    def generate_response(self, prompt: str) -> str:
        return f"[CloudAI Response]: Processed prompt: '{prompt[:50]}...'"
