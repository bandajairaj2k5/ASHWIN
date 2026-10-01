"""
ASHWIN AI Router (RULE-01, RULE-03, RULE-04, RULE-05, Section 4).
Routes scanned & classified context objects to Local or Cloud AI models according to strict privacy boundaries.
"""

from typing import Dict, Any, Optional, Protocol
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)


from ashwin.core.providers import (
    AIProvider,
    LocalAIProvider,
    CloudAIProvider,
    BaseCloudAIProvider,
    GeminiCloudProvider,
    ProviderError,
    ProviderCredentialError,
    ProviderUnavailableError,
)


class AIRouter:
    """
    Model-agnostic AI Router enforcing Section 4 rules, RULE-01, RULE-03, RULE-04, RULE-05.
    Sole model-delivery boundary. Accepts ONLY typed ScannedClassifiedContext.
    Cloud routing requires explicit per-request consent for non-public data.
    """

    def __init__(
        self,
        local_provider: Optional[AIProvider] = None,
        cloud_provider: Optional[AIProvider] = None
    ):
        self.local_provider = local_provider or LocalAIProvider()
        self.cloud_provider = cloud_provider or CloudAIProvider()
        self.local_available = True

    def set_local_availability(self, available: bool):
        self.local_available = available

    def process_context(
        self,
        context: ScannedClassifiedContext,
        user_cloud_consent: bool = False
    ) -> Dict[str, Any]:
        """
        Main gate (RULE-04, RULE-05). Accepts only valid ScannedClassifiedContext.
        """
        # Enforce RULE-04 & RULE-05 typing & gate check
        if not isinstance(context, ScannedClassifiedContext):
            raise RouterGateError("RULE-04 Violation: Object is not a valid ScannedClassifiedContext instance.")

        if not context.scanned or not context.scan_summary.get("healthy", False):
            raise RouterGateError("RULE-04 Violation: Context item missing valid scan state.")

        # RULE-03 check
        if context.data_class == DataClass.HIGHLY_PROTECTED:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter model context.")

        # Route determination
        target_provider = self._determine_route(context, user_cloud_consent)

        if target_provider is None:
            return {
                "status": "DENIED",
                "reason": "Missing cloud egress consent while local AI is unavailable or prohibited.",
                "user_prompt_required": True,
                "data_class": context.data_class.value,
                "source": context.source.value,
                "message": (
                    f"The local AI is unavailable. Processing this {context.data_class.value} data "
                    f"from {context.source.value} with cloud AI would send contents outside your device. "
                    "Allow this for this request?"
                )
            }

        response_text = target_provider.generate_response(context.content)

        return {
            "status": "SUCCESS",
            "provider_used": target_provider.name,
            "is_local": target_provider.is_local,
            "data_class": context.data_class.value,
            "source": context.source.value,
            "response": response_text,
        }

    def _determine_route(
        self,
        context: ScannedClassifiedContext,
        user_cloud_consent: bool
    ) -> Optional[AIProvider]:
        """
        Section 4 Routing Policy.
        """
        data_class = context.data_class

        # HIGHLY_PROTECTED is strictly blocked from model ingress
        if data_class == DataClass.HIGHLY_PROTECTED:
            return None

        # PUBLIC data: Cloud AI permitted
        if data_class == DataClass.PUBLIC:
            if self.cloud_provider:
                return self.cloud_provider
            if self.local_available and self.local_provider:
                return self.local_provider
            return None

        # PERSONAL data: Local preferred, cloud requires explicit per-request consent
        if data_class == DataClass.PERSONAL:
            if self.local_available and self.local_provider:
                return self.local_provider
            if user_cloud_consent or context.cloud_approved:
                return self.cloud_provider
            return None

        # PROTECTED data: Default Local AI, cloud requires explicit per-request consent
        if data_class == DataClass.PROTECTED:
            if self.local_available and self.local_provider:
                return self.local_provider
            if user_cloud_consent or context.cloud_approved:
                return self.cloud_provider
            return None

        return None
