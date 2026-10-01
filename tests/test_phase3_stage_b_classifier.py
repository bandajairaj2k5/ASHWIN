"""
Unit tests for Phase 3 / Stage B: Data Classification & Ingestion Pipeline.
"""

import unittest
from ashwin.core.classifier import InputClassifier
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner


class TestPhase3StageBClassifier(unittest.TestCase):

    def setUp(self):
        self.scanner = SecretScanner()
        self.classifier = InputClassifier(scanner=self.scanner)

    def test_typed_user_input_defaults_to_protected(self):
        raw_text = "What is the capital of France?"
        ctx = self.classifier.process_user_input(
            raw_text=raw_text,
            source=SourceDomain.PHONE,
            is_stt=False
        )

        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(ctx.source, SourceDomain.PHONE)
        self.assertEqual(ctx.content, raw_text)
        self.assertTrue(ctx.scanned)
        self.assertTrue(ctx.scan_summary.get("healthy"))
        self.assertEqual(ctx.metadata.get("input_type"), "TYPED_TEXT")
        self.assertFalse(ctx.cloud_approved)

    def test_stt_voice_input_defaults_to_protected(self):
        stt_transcript = "Schedule a meeting with the team tomorrow."
        ctx = self.classifier.process_user_input(
            raw_text=stt_transcript,
            source=SourceDomain.PHONE,
            is_stt=True
        )

        self.assertEqual(ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(ctx.metadata.get("input_type"), "STT")
        self.assertTrue(ctx.scanned)

    def test_secret_scanning_and_redaction_in_pipeline(self):
        text_with_api_key = "My OpenAI key is sk-1234567890abcdef123456 for testing."
        ctx = self.classifier.process_user_input(
            raw_text=text_with_api_key,
            source=SourceDomain.PHONE
        )

        self.assertNotIn("sk-1234567890abcdef123456", ctx.content)
        self.assertIn("[REDACTED:API_KEY]", ctx.content)
        self.assertEqual(ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(ctx.scan_summary.get("redaction_count"), 1)

    def test_unhealthy_scanner_blocks_context_creation(self):
        unhealthy_scanner = SecretScanner(healthy=False)
        unhealthy_classifier = InputClassifier(scanner=unhealthy_scanner)

        with self.assertRaises((RouterGateError, SecurityViolation)):
            unhealthy_classifier.process_user_input(
                raw_text="Hello world",
                source=SourceDomain.PHONE
            )

    def test_external_content_classification(self):
        # Public web content
        web_ctx = self.classifier.process_external_content(
            content="Public Wikipedia article on Python.",
            source=SourceDomain.WEB,
            default_class=DataClass.PUBLIC
        )
        self.assertEqual(web_ctx.data_class, DataClass.PUBLIC)
        self.assertEqual(web_ctx.source, SourceDomain.WEB)

        # Moto protected storage document
        moto_ctx = self.classifier.process_external_content(
            content="Confidential project roadmap notes.",
            source=SourceDomain.MOTO_STORAGE,
            default_class=DataClass.PROTECTED
        )
        self.assertEqual(moto_ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(moto_ctx.source, SourceDomain.MOTO_STORAGE)


if __name__ == "__main__":
    unittest.main()
