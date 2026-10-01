"""
Unit tests for Phase 3 / Stage E: Bounded Ephemeral Short-Term Memory.
"""

import unittest
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.memory import EphemeralMemoryStore, MemoryItem
from ashwin.core.router import AIRouter, LocalAIProvider
from ashwin.core.session import CoreSession


class TestPhase3StageEMemory(unittest.TestCase):

    def setUp(self):
        self.scanner = SecretScanner()
        self.memory = EphemeralMemoryStore(scanner=self.scanner, max_items=5, max_total_bytes=500)
        self.router = AIRouter()

    def _create_context(
        self,
        content: str,
        data_class: DataClass = DataClass.PROTECTED,
        source: SourceDomain = SourceDomain.PHONE,
        scanned: bool = True,
        healthy: bool = True
    ) -> ScannedClassifiedContext:
        return ScannedClassifiedContext(
            content=content,
            data_class=data_class,
            source=source,
            scanned=scanned,
            scan_summary={"healthy": healthy, "redaction_count": 0}
        )

    def test_ram_only_memory_insertion_and_recall(self):
        ctx1 = self._create_context("First user statement", data_class=DataClass.PERSONAL)
        ctx2 = self._create_context("Second user statement", data_class=DataClass.PERSONAL)

        self.memory.add_context(ctx1)
        self.memory.add_context(ctx2)

        self.assertEqual(self.memory.count, 2)
        recalled = self.memory.recall_context()

        self.assertIsInstance(recalled, ScannedClassifiedContext)
        self.assertIn("First user statement", recalled.content)
        self.assertIn("Second user statement", recalled.content)
        self.assertEqual(recalled.data_class, DataClass.PERSONAL)
        self.assertTrue(recalled.scanned)

    def test_fixed_item_count_bound_fifo_eviction(self):
        """When max_items (5) is exceeded, oldest items are evicted first (FIFO)."""
        for i in range(7):
            ctx = self._create_context(f"Item #{i}", data_class=DataClass.PROTECTED)
            self.memory.add_context(ctx)

        self.assertEqual(self.memory.count, 5)
        recalled = self.memory.recall_context()
        self.assertNotIn("Item #0", recalled.content)
        self.assertNotIn("Item #1", recalled.content)
        self.assertIn("Item #2", recalled.content)
        self.assertIn("Item #6", recalled.content)

    def test_utf8_byte_bound_fifo_eviction(self):
        """When aggregate UTF-8 bytes exceed max_total_bytes (100 bytes), oldest items are evicted."""
        small_mem = EphemeralMemoryStore(scanner=self.scanner, max_items=10, max_total_bytes=100)

        # 40 bytes each
        small_mem.add_context(self._create_context("A" * 40, data_class=DataClass.PUBLIC))
        small_mem.add_context(self._create_context("B" * 40, data_class=DataClass.PUBLIC))
        self.assertEqual(small_mem.count, 2)
        self.assertEqual(small_mem.total_bytes, 80)

        # Adding 40 bytes exceeds 100 bytes limit (80 + 40 = 120 -> evict oldest item 'A')
        small_mem.add_context(self._create_context("C" * 40, data_class=DataClass.PUBLIC))
        self.assertEqual(small_mem.count, 2)
        self.assertEqual(small_mem.total_bytes, 80)

        recalled = small_mem.recall_context()
        self.assertNotIn("A" * 40, recalled.content)
        self.assertIn("B" * 40, recalled.content)
        self.assertIn("C" * 40, recalled.content)

    def test_highest_classification_inheritance(self):
        """Composite memory recall inherits the highest classification among items."""
        # PUBLIC + PERSONAL -> PERSONAL
        mem1 = EphemeralMemoryStore(scanner=self.scanner)
        mem1.add_context(self._create_context("Public fact", data_class=DataClass.PUBLIC))
        mem1.add_context(self._create_context("Personal note", data_class=DataClass.PERSONAL))
        recalled1 = mem1.recall_context()
        self.assertEqual(recalled1.data_class, DataClass.PERSONAL)

        # PERSONAL + PROTECTED -> PROTECTED
        mem2 = EphemeralMemoryStore(scanner=self.scanner)
        mem2.add_context(self._create_context("Personal preference", data_class=DataClass.PERSONAL))
        mem2.add_context(self._create_context("Private document snippet", data_class=DataClass.PROTECTED))
        recalled2 = mem2.recall_context()
        self.assertEqual(recalled2.data_class, DataClass.PROTECTED)

    def test_secret_redaction_and_highly_protected_blocking(self):
        """Secrets are redacted before storage, and unredacted HIGHLY_PROTECTED context is blocked."""
        item = self.memory.add_user_input(raw_text="My secret API key is sk-1234567890abcdef123456")
        self.assertNotIn("sk-1234567890abcdef123456", item.content)
        self.assertIn("[REDACTED:API_KEY]", item.content)
        self.assertEqual(item.data_class, DataClass.PROTECTED)

        # Attempting to directly construct or inject HIGHLY_PROTECTED context is rejected
        with self.assertRaises(SecurityViolation):
            ScannedClassifiedContext(
                content="sensitive_token_123",
                data_class=DataClass.HIGHLY_PROTECTED,
                source=SourceDomain.PHONE,
                scanned=True,
                scan_summary={"healthy": True}
            )

    def test_unscanned_context_blocked_at_insertion(self):
        """RULE-04: Context lacking scan state is rejected from memory."""
        with self.assertRaises((RouterGateError, SecurityViolation)):
            ScannedClassifiedContext(
                content="Unscanned text",
                data_class=DataClass.PROTECTED,
                source=SourceDomain.PHONE,
                scanned=False,
                scan_summary={"healthy": True}
            )

    def test_unhealthy_scanner_fails_closed(self):
        """Unhealthy scanner blocks raw user input memory insertion."""
        unhealthy_scanner = SecretScanner(healthy=False)
        unhealthy_mem = EphemeralMemoryStore(scanner=unhealthy_scanner)

        with self.assertRaises((RouterGateError, SecurityViolation)):
            unhealthy_mem.add_user_input(raw_text="Hello world")

    def test_explicit_clear_and_reset_wipes_all_memory(self):
        self.memory.add_context(self._create_context("Some memory", data_class=DataClass.PERSONAL))
        self.assertEqual(self.memory.count, 1)
        self.assertGreater(self.memory.total_bytes, 0)

        self.memory.clear()
        self.assertEqual(self.memory.count, 0)
        self.assertEqual(self.memory.total_bytes, 0)

        recalled = self.memory.recall_context()
        self.assertEqual(recalled.content, "")

    def test_session_lifecycle_clears_memory(self):
        session = CoreSession()
        session.memory_store.add_user_input(raw_text="Remember my preference")
        self.assertEqual(session.memory_store.count, 1)

        session.reset_session()
        self.assertEqual(session.memory_store.count, 0)

        session.memory_store.add_user_input(raw_text="Second preference")
        self.assertEqual(session.memory_store.count, 1)

        session.terminate_session()
        self.assertEqual(session.memory_store.count, 0)

    def test_recalled_context_passes_through_airouter(self):
        """Memory recall context passes cleanly into AIRouter following Section 4 policy."""
        self.memory.add_context(self._create_context("User likes concise responses", data_class=DataClass.PROTECTED))
        recalled = self.memory.recall_context()

        res = self.router.process_context(recalled, user_cloud_consent=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["provider_used"], "LocalAI")
        self.assertTrue(res["is_local"])


if __name__ == "__main__":
    unittest.main()
