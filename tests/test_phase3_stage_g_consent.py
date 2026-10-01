"""
Unit tests for Phase 3 / Stage G: Per-Request Cloud Consent & Unified Core Turn Ingress Boundary.
(Section 4.5, Section 4.7, RULE-01, RULE-02, RULE-03, RULE-04, RULE-05, Section 12).
"""

import unittest
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    SecurityViolation,
    RouterGateError,
)
from ashwin.core.session import CoreSession
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.classifier import InputClassifier
from ashwin.core.memory import EphemeralMemoryStore
from ashwin.core.router import AIRouter
from ashwin.core.consent import (
    ConsentMetadata,
    ConsentDecisionType,
    CloudConsentToken,
    ConsentCoordinator,
    CallbackConsentCoordinator,
)


class TestPhase3StageGConsent(unittest.TestCase):

    def setUp(self):
        self.session = CoreSession()

    def test_stage_g_01_local_ai_path_requires_no_consent_prompt(self):
        """RULE-01 / Section 4.4: PROTECTED typed input routes to LocalAI without prompting for cloud consent."""
        prompted = False

        def mock_consent(meta: ConsentMetadata):
            nonlocal prompted
            prompted = True
            return ConsentDecisionType.DENIED

        coordinator = CallbackConsentCoordinator(mock_consent)
        res = self.session.execute_turn(
            raw_text="Hello, how is the weather?",
            source=SourceDomain.PHONE,
            is_stt=False,
            consent_coordinator=coordinator
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "LocalAI")
        self.assertTrue(res["is_local"])
        self.assertFalse(prompted)
        self.assertEqual(self.session.memory_store.count, 1)

    def test_stage_g_02_local_ai_down_triggers_minimal_metadata_consent_request(self):
        """Section 4.5 / Section 4.7: When local AI is down, consent prompt receives minimal metadata only (zero raw content)."""
        self.session.router.set_local_availability(False)
        captured_metadata = None

        def mock_consent(meta: ConsentMetadata):
            nonlocal captured_metadata
            captured_metadata = meta
            return ConsentDecisionType.GRANTED_ONCE

        coordinator = CallbackConsentCoordinator(mock_consent)
        secret_input = "My personal secret query"
        res = self.session.execute_turn(
            raw_text=secret_input,
            source=SourceDomain.PHONE,
            is_stt=False,
            consent_coordinator=coordinator
        )

        self.assertIsNotNone(captured_metadata)
        self.assertEqual(captured_metadata.source_domain, SourceDomain.PHONE)
        self.assertEqual(captured_metadata.data_class, DataClass.PROTECTED)
        self.assertEqual(captured_metadata.target_provider, "CloudAI")
        # Metadata must NOT contain the raw input text
        self.assertNotIn(secret_input, captured_metadata.rationale)
        self.assertNotIn(secret_input, str(captured_metadata.to_dict()))

    def test_stage_g_03_consent_granted_once_routes_through_airouter_to_cloud(self):
        """RULE-04 / RULE-05 / Section 4.5: GRANTED_ONCE dispatches through AIRouter and consumes the token."""
        self.session.router.set_local_availability(False)

        def mock_consent(meta: ConsentMetadata):
            return ConsentDecisionType.GRANTED_ONCE

        coordinator = CallbackConsentCoordinator(mock_consent)
        res = self.session.execute_turn(
            raw_text="Help me draft an email",
            source=SourceDomain.PHONE,
            is_stt=False,
            consent_coordinator=coordinator
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "CloudAI")
        self.assertFalse(res["is_local"])

        # Verify audit logger recorded the events
        logged_types = [e.event_type for e in self.session.audit_logger.get_entries()]
        self.assertIn("CLOUD_CONSENT_REQUEST", logged_types)
        self.assertIn("CLOUD_CONSENT_GRANTED", logged_types)
        self.assertIn("MODEL_DELIVERY_SUCCESS", logged_types)

    def test_stage_g_04_consent_denied_halts_egress_and_returns_honest_message(self):
        """Section 2.5 / Section 4.5: When user denies cloud consent, zero cloud calls occur and honest message is returned."""
        self.session.router.set_local_availability(False)

        def mock_consent(meta: ConsentMetadata):
            return ConsentDecisionType.DENIED

        coordinator = CallbackConsentCoordinator(mock_consent)
        res = self.session.execute_turn(
            raw_text="Translate my document",
            source=SourceDomain.PHONE,
            is_stt=False,
            consent_coordinator=coordinator
        )

        self.assertEqual(res["status"], "DENIED")
        self.assertIn("denied by user", res["reason"].lower())
        self.assertFalse(res["user_prompt_required"])

        logged_types = [e.event_type for e in self.session.audit_logger.get_entries()]
        self.assertIn("CLOUD_CONSENT_REQUEST", logged_types)
        self.assertIn("CLOUD_CONSENT_DENIED", logged_types)
        self.assertNotIn("MODEL_DELIVERY_SUCCESS", logged_types)

    def test_stage_g_05_consent_is_strictly_ephemeral_and_does_not_persist(self):
        """Section 4.5: GRANTED_ONCE applies only to the current turn; next turn prompts anew."""
        self.session.router.set_local_availability(False)
        consent_calls = 0

        def mock_consent(meta: ConsentMetadata):
            nonlocal consent_calls
            consent_calls += 1
            return ConsentDecisionType.GRANTED_ONCE

        coordinator = CallbackConsentCoordinator(mock_consent)

        # Turn 1
        res1 = self.session.execute_turn("Query 1", consent_coordinator=coordinator)
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertEqual(consent_calls, 1)

        # Turn 2 must prompt again (no stored or persistent consent)
        res2 = self.session.execute_turn("Query 2", consent_coordinator=coordinator)
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertEqual(consent_calls, 2)

    def test_stage_g_06_token_cannot_be_reused_after_consumption(self):
        """Tokens are single-use; reusing a consumed token raises SecurityViolation."""
        token = CloudConsentToken(
            request_id="REQ_1",
            source_domain=SourceDomain.PHONE,
            data_class=DataClass.PROTECTED,
            target_provider="CloudAI"
        )
        self.assertFalse(token.is_consumed)
        token.consume()
        self.assertTrue(token.is_consumed)

        with self.assertRaises(SecurityViolation):
            token.consume()

    def test_stage_g_07_token_mismatch_fails_closed(self):
        """Tokens bound to wrong provider, data class, or domain fail validation."""
        token = CloudConsentToken(
            request_id="REQ_1",
            source_domain=SourceDomain.PHONE,
            data_class=DataClass.PERSONAL,
            target_provider="CloudAI"
        )
        ctx = ScannedClassifiedContext(
            content="Protected text",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.PHONE,
            scanned=True,
            scan_summary={"healthy": True},
            cloud_approved=False
        )
        self.assertFalse(token.is_valid_for(ctx, target_provider="CloudAI"))
        self.assertFalse(token.is_valid_for(ctx, target_provider="OtherProvider"))

    def test_stage_g_08_highly_protected_blocks_before_consent_memory_or_router(self):
        """RULE-03: HIGHLY_PROTECTED data fails closed immediately without calling consent coordinator or memory store."""
        prompted = False

        def mock_consent(meta: ConsentMetadata):
            nonlocal prompted
            prompted = True
            return ConsentDecisionType.GRANTED_ONCE

        coordinator = CallbackConsentCoordinator(mock_consent)

        # Scanner returning HIGHLY_PROTECTED (e.g. scanner unhealthy or unredactable)
        self.session.scanner.set_health(False)

        with self.assertRaises(Exception):
            self.session.execute_turn(
                raw_text="Attempting ingress while scanner reports HIGHLY_PROTECTED / unhealthy",
                source=SourceDomain.PHONE,
                consent_coordinator=coordinator
            )

        self.assertFalse(prompted)
        self.assertEqual(self.session.memory_store.count, 0)


if __name__ == "__main__":
    unittest.main()
