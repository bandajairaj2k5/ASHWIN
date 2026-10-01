"""
ASHWIN Cloud Consent Subsystem (Phase 3 / Stage G, Section 4.5, Section 4.7, RULE-01, RULE-04, RULE-05).
Implements structured, request-bound ephemeral cloud consent tokens and minimal metadata coordination.
"""

import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, Callable
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    SecurityViolation,
)


class ConsentDecisionType(Enum):
    GRANTED_ONCE = "GRANTED_ONCE"
    DENIED = "DENIED"


@dataclass(frozen=True)
class ConsentMetadata:
    """
    Minimal metadata presented for user consent resolution.
    Strictly contains NO raw context text or private data strings (Section 4.7).
    """
    source_domain: SourceDomain
    data_class: DataClass
    target_provider: str
    rationale: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain.value,
            "data_class": self.data_class.value,
            "target_provider": self.target_provider,
            "rationale": self.rationale,
            "request_id": self.request_id,
        }


@dataclass
class CloudConsentToken:
    """
    Structured, ephemeral authorization bound to the exact request/turn,
    target provider, source domain, data classification, and context identity.
    Consumed immediately upon use (Section 4.5).
    """
    request_id: str
    source_domain: SourceDomain
    data_class: DataClass
    target_provider: str
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    _consumed: bool = False

    @property
    def is_consumed(self) -> bool:
        return self._consumed

    def is_valid_for(
        self,
        context: ScannedClassifiedContext,
        target_provider: str,
        expected_request_id: Optional[str] = None
    ) -> bool:
        """
        Validates that this ephemeral token matches the exact context, classification,
        source domain, and target provider of the current request.
        """
        if self._consumed:
            return False
        if expected_request_id and self.request_id != expected_request_id:
            return False
        if self.source_domain != context.source:
            return False
        if self.data_class != context.data_class:
            return False
        if self.target_provider != target_provider:
            return False
        return True

    def consume(self):
        """Consumes the token so it cannot be reused."""
        if self._consumed:
            raise SecurityViolation("ConsentToken has already been consumed.")
        self._consumed = True


class ConsentCoordinator:
    """
    Interface for interactive consent resolution.
    Dispatches minimal metadata and returns an ephemeral CloudConsentToken upon approval.
    """

    def request_consent(self, metadata: ConsentMetadata) -> Optional[CloudConsentToken]:
        """
        Presents minimal metadata to user.
        If approved: returns a newly generated CloudConsentToken bound to metadata.
        If denied: returns None.
        """
        raise NotImplementedError("Subclasses must implement request_consent.")


class CallbackConsentCoordinator(ConsentCoordinator):
    """Consent coordinator backed by a callable function/handler."""

    def __init__(self, handler: Callable[[ConsentMetadata], ConsentDecisionType]):
        self.handler = handler

    def request_consent(self, metadata: ConsentMetadata) -> Optional[CloudConsentToken]:
        decision = self.handler(metadata)
        if decision == ConsentDecisionType.GRANTED_ONCE:
            return CloudConsentToken(
                request_id=metadata.request_id,
                source_domain=metadata.source_domain,
                data_class=metadata.data_class,
                target_provider=metadata.target_provider,
            )
        return None
