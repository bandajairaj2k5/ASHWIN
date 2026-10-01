"""
Unit tests for Phase 3 / Stage C: AIRouter & Provider Routing Policy (RULE-01, RULE-03, RULE-04, RULE-05, Section 4).
"""

import unittest
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.router import (
    AIRouter,
    AIProvider,
    LocalAIProvider,
    CloudAIProvider,
)


class MockCustomAIProvider:
    def __init__(self, name: str, is_local: bool):
        self.name = name
        self.is_local = is_local
        self.calls = []

    def generate_response(self, prompt: str) -> str:
        self.calls.append(prompt)
        return f"[{self.name} Output]: {prompt}"


class TestPhase3StageCRouter(unittest.TestCase):

    def setUp(self):
        self.local_mock = MockCustomAIProvider("MockLocalAI", is_local=True)
        self.cloud_mock = MockCustomAIProvider("MockCloudAI", is_local=False)
        self.router = AIRouter(
            local_provider=self.local_mock,
            cloud_provider=self.cloud_mock
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

    def test_raw_string_rejected_by_gate(self):
        """RULE-04: Non-ScannedClassifiedContext types are strictly rejected."""
        with self.assertRaises(RouterGateError):
            self.router.process_context("Raw unclassified prompt text")  # type: ignore

        with self.assertRaises(RouterGateError):
            self.router.process_context({"content": "Dict bypass attempt"})  # type: ignore

    def test_unscanned_or_unhealthy_scan_rejected(self):
        """RULE-04: Unscanned or unhealthy contexts are rejected."""
        with self.assertRaises((RouterGateError, SecurityViolation)):
            ScannedClassifiedContext(
                content="Unscanned prompt",
                data_class=DataClass.PROTECTED,
                source=SourceDomain.PHONE,
                scanned=False,
                scan_summary={"healthy": True}
            )

        with self.assertRaises((RouterGateError, SecurityViolation)):
            ScannedClassifiedContext(
                content="Unhealthy scan prompt",
                data_class=DataClass.PROTECTED,
                source=SourceDomain.PHONE,
                scanned=True,
                scan_summary={"healthy": False}
            )

    def test_highly_protected_rejected_from_model_context(self):
        """RULE-03: HIGHLY_PROTECTED data is blocked from entering model context."""
        with self.assertRaises(SecurityViolation):
            ScannedClassifiedContext(
                content="AKIAIOSFODNN7EXAMPLE",
                data_class=DataClass.HIGHLY_PROTECTED,
                source=SourceDomain.PHONE,
                scanned=True,
                scan_summary={"healthy": True}
            )

    def test_protected_routes_to_local_ai_by_default(self):
        """RULE-01 / Section 4.2 / Section 4.4: PROTECTED routes to Local AI by default."""
        ctx = self._create_valid_context(
            content="Read my private notes",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.MOTO_STORAGE
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "MockLocalAI")
        self.assertTrue(res["is_local"])
        self.assertEqual(len(self.local_mock.calls), 1)
        self.assertEqual(len(self.cloud_mock.calls), 0)

    def test_protected_denied_when_local_unavailable_and_no_cloud_consent(self):
        """Section 4.5: If local AI is unavailable and no consent exists, deny and ask; no silent fallback."""
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
        self.assertIn("Missing cloud egress consent", res["reason"])
        self.assertEqual(len(self.local_mock.calls), 0)
        self.assertEqual(len(self.cloud_mock.calls), 0)

    def test_personal_denied_when_local_unavailable_and_no_cloud_consent(self):
        """Section 4.5: If local AI is unavailable and no consent exists, PERSONAL data is denied."""
        self.router.set_local_availability(False)
        ctx = self._create_valid_context(
            content="Personal preference notes",
            data_class=DataClass.PERSONAL,
            source=SourceDomain.PHONE,
            cloud_approved=False
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)

        self.assertEqual(res["status"], "DENIED")
        self.assertTrue(res["user_prompt_required"])
        self.assertEqual(len(self.local_mock.calls), 0)
        self.assertEqual(len(self.cloud_mock.calls), 0)

    def test_protected_routes_to_cloud_with_explicit_request_consent(self):
        """Section 4.5: Explicit per-request consent allows cloud processing when local AI is unavailable."""
        self.router.set_local_availability(False)
        ctx = self._create_valid_context(
            content="Summarize my document",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.LAPTOP,
            cloud_approved=False
        )
        res = self.router.process_context(ctx, user_cloud_consent=True)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "MockCloudAI")
        self.assertFalse(res["is_local"])
        self.assertEqual(len(self.cloud_mock.calls), 1)

    def test_protected_routes_to_cloud_with_pre_approved_context(self):
        """Section 4.5: Context with cloud_approved=True routes to cloud when local is unavailable."""
        self.router.set_local_availability(False)
        ctx = self._create_valid_context(
            content="Cloud-approved document",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.PHONE,
            cloud_approved=True
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "MockCloudAI")
        self.assertFalse(res["is_local"])
        self.assertEqual(len(self.cloud_mock.calls), 1)

    def test_personal_routes_to_cloud_with_explicit_consent(self):
        """Section 4.5: PERSONAL data routes to cloud when local is unavailable with explicit consent."""
        self.router.set_local_availability(False)
        ctx = self._create_valid_context(
            content="Favorite color note",
            data_class=DataClass.PERSONAL,
            source=SourceDomain.PHONE,
            cloud_approved=False
        )
        res = self.router.process_context(ctx, user_cloud_consent=True)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "MockCloudAI")
        self.assertFalse(res["is_local"])
        self.assertEqual(len(self.cloud_mock.calls), 1)

    def test_public_data_routes_to_cloud_ai(self):
        """Section 4.4: PUBLIC data routes to Cloud AI permitted."""
        ctx = self._create_valid_context(
            content="Public weather query",
            data_class=DataClass.PUBLIC,
            source=SourceDomain.WEB
        )
        res = self.router.process_context(ctx, user_cloud_consent=False)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "MockCloudAI")
        self.assertFalse(res["is_local"])
        self.assertEqual(len(self.cloud_mock.calls), 1)

    def test_no_implicit_cloud_fallback(self):
        """Invariants 7 & 8: Under no circumstances does PROTECTED data silently fall back to cloud."""
        self.router.set_local_availability(False)
        ctx = self._create_valid_context(
            content="Sensitive internal communication",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.GMAIL,
            cloud_approved=False
        )

        for _ in range(5):
            res = self.router.process_context(ctx, user_cloud_consent=False)
            self.assertEqual(res["status"], "DENIED")

        self.assertEqual(len(self.cloud_mock.calls), 0)


if __name__ == "__main__":
    unittest.main()
