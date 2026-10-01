"""
Automated Security Tests for Phase 3 / Stage H: Moto Storage Integration into Core / Conversational Pipeline.
Verifies Section 2.4, Section 2.5, Section 4.3, Section 4.5, Section 6.1, Section 6.2, Section 6.3,
Section 9.4, Section 9.7, Section 9.8, Section 10, RULE-01, RULE-03, RULE-04, RULE-05, RULE-09, RULE-14, RULE-15.
"""

import unittest
import os
import shutil
import tempfile
import json
from typing import Dict, Any, Optional

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.classifier import InputClassifier
from ashwin.core.router import AIRouter
from ashwin.core.memory import EphemeralMemoryStore, MemoryItem
from ashwin.core.consent import ConsentCoordinator, ConsentMetadata, CloudConsentToken
from ashwin.core.session import CoreSession
from ashwin.core.storage import (
    StorageConnector,
    MotoStorageAdapter,
    StorageOfflineError,
    StoragePermissionError,
    StorageSecurityContractViolation
)
from ashwin.moto_endpoint.moto_connector import MotoConnector
from ashwin.moto_endpoint.server import MotoStorageServer


class MockConsentCoordinator(ConsentCoordinator):
    """Test coordinator capturing metadata and returning deterministic decision."""

    def __init__(self, grant: bool = True):
        self.grant = grant
        self.captured_metadata: Optional[ConsentMetadata] = None
        self.request_count = 0

    def request_consent(self, metadata: ConsentMetadata) -> Optional[CloudConsentToken]:
        self.captured_metadata = metadata
        self.request_count += 1
        if self.grant:
            return CloudConsentToken(
                request_id=metadata.request_id,
                source_domain=metadata.source_domain,
                data_class=metadata.data_class,
                target_provider=metadata.target_provider
            )
        return None


class TestPhase3StageHMotoIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ashwin_stage_h_test_")
        
        # Initialize Moto server and connector (server jail uses root_dir=self.test_dir)
        self.server = MotoStorageServer(root_dir=self.test_dir)
        self.moto_connector = MotoConnector(server=self.server)
        self.moto_connector.run_feasibility_gate(True, True, True)
        self.moto_connector.pair_device(True)

        # Create test documents inside the server jail's Documents folder
        self.docs_dir = os.path.join(self.server.jail.canonical_root, "Documents")
        os.makedirs(self.docs_dir, exist_ok=True)

        self.doc_path = os.path.join(self.docs_dir, "report.txt")
        with open(self.doc_path, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL: Q3 Project Architecture Report for ASHWIN system.")

        # Create document with synthetic non-functional secret for RULE-09 test
        self.secret_doc_path = os.path.join(self.docs_dir, "config.txt")
        self.synthetic_secret = "AIzaSyDummyTestKeyForScannerVerification12345"
        with open(self.secret_doc_path, "w", encoding="utf-8") as f:
            f.write(f"System configuration api_key={self.synthetic_secret} for backup.")

        # Initialize Storage Adapter and Core Session
        self.storage_adapter = MotoStorageAdapter(self.moto_connector)
        self.session = CoreSession(storage_connector=self.storage_adapter)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_stage_h_moto_connector_security_contract(self):
        """1. StorageConnector security contract: returns ScannedClassifiedContext with PROTECTED class."""
        self.storage_adapter.set_access_permission(True)
        ctx = self.storage_adapter.read_file("Documents/report.txt")
        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(ctx.source, SourceDomain.MOTO_STORAGE)
        self.assertTrue(ctx.scanned)
        self.assertTrue(ctx.scan_summary.get("healthy"))
        self.assertIn("location_for_model", ctx.metadata)
        self.assertFalse(ctx.metadata["location_for_model"].startswith("C:\\"))
        self.assertFalse(ctx.metadata["location_for_model"].startswith("/"))

    def test_stage_h_moto_access_permission_precedes_all_queries(self):
        """2. Section 6.3: No query may execute before access permission is granted."""
        self.storage_adapter.set_access_permission(False)
        with self.assertRaises(StoragePermissionError):
            self.storage_adapter.list_files("")

        with self.assertRaises(StoragePermissionError):
            self.storage_adapter.read_file("Documents/report.txt")

    def test_stage_h_moto_access_permission_denied_halts_cleanly(self):
        """3. Denying access permission returns honest denial without performing network requests."""
        def deny_prompt(prompt_text: str) -> bool:
            self.assertIn("Your private Moto storage requires permission. May I access it?", prompt_text)
            return False

        res = self.session.execute_storage_turn(
            command_text="List files on Moto",
            operation="list",
            permission_prompt_callback=deny_prompt
        )
        self.assertEqual(res["status"], "DENIED")
        self.assertIn("permission was denied", res["message"])
        self.assertFalse(self.storage_adapter.get_access_permission())

    def test_stage_h_moto_access_permission_scope_non_persistence(self):
        """4. Moto access permission is not persisted across session reset/termination."""
        self.storage_adapter.set_access_permission(True)
        self.assertTrue(self.storage_adapter.get_access_permission())

        # Session reset revokes access permission
        self.session.reset_session()
        self.assertFalse(self.storage_adapter.get_access_permission())

        # Session terminate revokes access permission
        self.storage_adapter.set_access_permission(True)
        self.session.terminate_session()
        self.assertFalse(self.storage_adapter.get_access_permission())

    def test_stage_h_moto_raw_content_blocked_from_memory(self):
        """5. Raw Moto bytes never enter EphemeralMemoryStore; only ScannedClassifiedContext enters."""
        def allow_prompt(prompt_text: str) -> bool:
            return True

        res = self.session.execute_storage_turn(
            command_text="Read my report from Moto",
            operation="read",
            target_path="Documents/report.txt",
            permission_prompt_callback=allow_prompt
        )
        self.assertEqual(res["status"], "SUCCESS")

        # Check EphemeralMemoryStore items
        items = self.session.memory_store._items
        self.assertGreater(len(items), 0)
        for item in items:
            self.assertIsInstance(item, MemoryItem)
            self.assertTrue(item.scanned)
            self.assertNotEqual(item.data_class, DataClass.HIGHLY_PROTECTED)

    def test_stage_h_moto_command_and_content_separation(self):
        """6. User command context (PHONE) and retrieved Moto context (MOTO_STORAGE) remain separate."""
        def allow_prompt(prompt_text: str) -> bool:
            return True

        self.session.execute_storage_turn(
            command_text="Fetch private Q3 report from Moto",
            operation="read",
            target_path="Documents/report.txt",
            permission_prompt_callback=allow_prompt
        )

        items = self.session.memory_store._items
        sources = [item.source for item in items]
        self.assertIn(SourceDomain.PHONE, sources)
        self.assertIn(SourceDomain.MOTO_STORAGE, sources)

        # Verify command context and storage context
        phone_item = next(item for item in items if item.source == SourceDomain.PHONE)
        moto_item = next(item for item in items if item.source == SourceDomain.MOTO_STORAGE)
        self.assertIn("Fetch private Q3 report", phone_item.content)
        self.assertIn("CONFIDENTIAL: Q3 Project Architecture Report", moto_item.content)

    def test_stage_h_moto_metadata_rule14_and_location_rule15(self):
        """7. RULE-14 metadata allowlist and RULE-15 safe location formatting."""
        self.storage_adapter.set_access_permission(True)
        list_ctx = self.storage_adapter.list_files("Documents")
        self.assertEqual(list_ctx.source, SourceDomain.MOTO_STORAGE)
        self.assertEqual(list_ctx.data_class, DataClass.PROTECTED)

        # Check metadata fields conform to allowlist
        allowed_keys = {"name", "size", "date", "type", "scope_label", "location_for_model"}
        for k in list_ctx.metadata.keys():
            self.assertIn(k, allowed_keys)

        # Check RULE-15 safe location
        read_ctx = self.storage_adapter.read_file("Documents/report.txt")
        self.assertEqual(read_ctx.metadata["location_for_model"], "MOTO_STORAGE/report.txt")

    def test_stage_h_moto_secret_redaction_rule09(self):
        """8. RULE-09: Synthetic secrets in Moto files are redacted before model ingress."""
        self.storage_adapter.set_access_permission(True)
        ctx = self.storage_adapter.read_file("Documents/config.txt")
        self.assertNotIn(self.synthetic_secret, ctx.content)
        self.assertIn("[REDACTED:API_KEY]", ctx.content)
        self.assertTrue(ctx.scanned)

        # Model routing uses redacted text
        res = self.session.router.process_context(ctx)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertNotIn(self.synthetic_secret, res.get("response", ""))

    def test_stage_h_moto_cloud_consent_gate_integration(self):
        """9. Cloud consent escalation for Moto storage context when Local AI is unavailable."""
        self.storage_adapter.set_access_permission(True)
        self.session.router.set_local_availability(False)

        coord = MockConsentCoordinator(grant=True)
        res = self.session.execute_storage_turn(
            command_text="Read report via cloud",
            operation="read",
            target_path="Documents/report.txt",
            permission_prompt_callback=lambda p: True,
            consent_coordinator=coord
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["is_local"])
        self.assertIsNotNone(coord.captured_metadata)
        self.assertEqual(coord.captured_metadata.source_domain, SourceDomain.MOTO_STORAGE)
        self.assertEqual(coord.captured_metadata.data_class, DataClass.PROTECTED)
        # Verify minimal metadata (no raw content in rationale/target)
        self.assertNotIn("Q3 Project Architecture", coord.captured_metadata.rationale)

        # Restore Local AI
        self.session.router.set_local_availability(True)

    def test_stage_h_moto_offline_honest_handling(self):
        """10. Section 2.4 & 2.5: Offline storage gives exact message and non-Moto turns continue."""
        # Unpair/break storage connector to simulate offline
        self.moto_connector.paired = False

        res = self.session.execute_storage_turn(
            command_text="Read report while offline",
            operation="read",
            target_path="Documents/report.txt",
            permission_prompt_callback=lambda p: True
        )

        self.assertEqual(res["status"], "OFFLINE")
        self.assertEqual(res["message"], "Your private storage server is currently unavailable.")

        # Storage independence (Section 2.4): Ordinary Core conversation turn must continue to work
        core_turn_res = self.session.execute_turn(
            raw_text="What is the capital of France?",
            source=SourceDomain.PHONE
        )
        self.assertEqual(core_turn_res["status"], "SUCCESS")
        self.assertIn("France", core_turn_res.get("response", ""))


if __name__ == "__main__":
    unittest.main()
