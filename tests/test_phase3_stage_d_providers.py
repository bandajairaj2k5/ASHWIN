"""
Unit tests for Phase 3 / Stage D: AI Provider Interfaces & Replaceable Cloud Abstraction.
"""

import unittest
import inspect
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.credentials import CredentialStore
from ashwin.core.providers import (
    AIProvider,
    LocalAIProvider,
    BaseCloudAIProvider,
    GeminiCloudProvider,
    CloudAIProvider,
    ProviderError,
    ProviderCredentialError,
    ProviderUnavailableError,
)
from ashwin.core.router import AIRouter


class CustomAlternativeCloudProvider(BaseCloudAIProvider):
    name = "CustomCloudProvider"
    is_local = False

    def generate_response(self, prompt: str) -> str:
        return f"[CustomCloud Output]: {prompt}"


class TestPhase3StageDProviders(unittest.TestCase):

    def setUp(self):
        self.cred_store = CredentialStore()
        self.local_provider = LocalAIProvider(model_identifier="local-qwen")
        self.gemini_provider = GeminiCloudProvider(
            credential_store=self.cred_store,
            model_identifier="gemini-1.5-flash"
        )
        self.router = AIRouter(
            local_provider=self.local_provider,
            cloud_provider=self.gemini_provider
        )

    def _create_valid_context(
        self,
        content: str = "Test prompt content",
        data_class: DataClass = DataClass.PROTECTED,
        source: SourceDomain = SourceDomain.PHONE,
        cloud_approved: bool = False
    ) -> ScannedClassifiedContext:
        return ScannedClassifiedContext(
            content=content,
            data_class=data_class,
            source=source,
            cloud_approved=cloud_approved,
            scanned=True,
            scan_summary={"healthy": True, "redaction_count": 0}
        )

    def test_gemini_provider_retrieves_key_from_credential_store(self):
        """GeminiCloudProvider retrieves its API key from CredentialStore."""
        self.cred_store.set_cloud_api_key("AIzaSy-TEST_SECURE_GEMINI_API_KEY_12345")
        response = self.gemini_provider.generate_response("Hello Gemini")
        self.assertIn("GeminiCloudAI Response", response)

    def test_gemini_provider_missing_credential_raises_error(self):
        """Missing API key in CredentialStore raises ProviderCredentialError (fail-closed)."""
        with self.assertRaises(ProviderCredentialError) as cm:
            self.gemini_provider.generate_response("Test prompt")
        self.assertIn("missing", str(cm.exception).lower())

    def test_gemini_provider_unconfigured_credential_store_raises_error(self):
        """GeminiCloudProvider initialized without CredentialStore raises ProviderCredentialError."""
        provider_no_store = GeminiCloudProvider(credential_store=None)
        with self.assertRaises(ProviderCredentialError) as cm:
            provider_no_store.generate_response("Test prompt")
        self.assertIn("credentialstore is not configured", str(cm.exception).lower())

    def test_no_direct_credential_injection_path(self):
        """GeminiCloudProvider constructor strictly prohibits direct api_key parameter bypass."""
        init_sig = inspect.signature(GeminiCloudProvider.__init__)
        self.assertNotIn("api_key", init_sig.parameters, "Constructor must not accept direct api_key parameter.")

    def test_credential_leakage_prevention(self):
        """Ensures secrets are never reflected in responses or exceptions."""
        secret_key = "AIzaSy-SUPER_CONFIDENTIAL_KEY_9999"
        self.cred_store.set_cloud_api_key(secret_key)
        response = self.gemini_provider.generate_response("What is the weather?")
        self.assertNotIn(secret_key, response)

    def test_cloud_provider_replaceability(self):
        """Proves AIRouter is not hardcoded to Gemini and accepts alternative cloud providers."""
        custom_cloud = CustomAlternativeCloudProvider()
        router_with_custom = AIRouter(
            local_provider=self.local_provider,
            cloud_provider=custom_cloud
        )
        router_with_custom.set_local_availability(False)

        ctx = self._create_valid_context(
            content="Translate this sentence",
            data_class=DataClass.PROTECTED,
            cloud_approved=True
        )
        res = router_with_custom.process_context(ctx, user_cloud_consent=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "CustomCloudProvider")

    def test_router_authorization_gate_blocks_before_cloud_provider(self):
        """Router gate protects CloudAIProvider from receiving unvalidated input."""
        self.cred_store.set_cloud_api_key("AIzaSy-VALID_KEY")

        # Unscanned context is blocked by router gate
        with self.assertRaises((RouterGateError, SecurityViolation)):
            self.router.process_context("Raw String Input Attempt")  # type: ignore

    def test_local_ai_is_default_destination_for_protected_data(self):
        """PROTECTED data defaults to LocalAI even when Gemini cloud is configured."""
        self.cred_store.set_cloud_api_key("AIzaSy-VALID_KEY")
        ctx = self._create_valid_context(
            content="Sensitive local note",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.PHONE
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "LocalAI")
        self.assertTrue(res["is_local"])

    def test_no_silent_fallback_to_gemini_when_local_unavailable(self):
        """When local AI is unavailable and no cloud consent is given, request is DENIED."""
        self.cred_store.set_cloud_api_key("AIzaSy-VALID_KEY")
        self.router.set_local_availability(False)

        ctx = self._create_valid_context(
            content="Private schedule",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.CALENDAR,
            cloud_approved=False
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)
        self.assertEqual(res["status"], "DENIED")
        self.assertTrue(res["user_prompt_required"])

    def test_gemini_invoked_with_explicit_cloud_consent(self):
        """Gemini is invoked when local AI is unavailable and explicit consent is provided."""
        self.cred_store.set_cloud_api_key("AIzaSy-VALID_KEY")
        self.router.set_local_availability(False)

        ctx = self._create_valid_context(
            content="Summarize my email",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.GMAIL,
            cloud_approved=False
        )
        res = self.router.process_context(ctx, user_cloud_consent=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "GeminiCloudAI")
        self.assertFalse(res["is_local"])


if __name__ == "__main__":
    unittest.main()
