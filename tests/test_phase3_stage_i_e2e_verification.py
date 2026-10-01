"""
Master Automated End-to-End Integration & Final Phase 3 Verification Suite (Phase 3 / Stage I).
Verifies complete cross-subsystem pipelines: typed, voice, Moto storage, AIRouter, EphemeralMemoryStore,
SecretScanner, InputClassifier, CloudConsentToken, fail-closed boundaries, and lifecycle management.
ASHWIN-SPEC v1.0.1 (RULE-01 to RULE-15, Section 2.4, 2.5, 4.3, 4.5, 5, 6, 7, 9, 10, 11, 14, 15).
"""

import unittest
import os
import shutil
import tempfile
import json
from typing import Dict, Any, Optional, List

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
from ashwin.core.voice import VoiceSubsystem, OnDeviceSTTEngine, OnDeviceTTSEngine
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
    """Test consent coordinator capturing metadata and recording decision."""

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


class CustomMockSTT(OnDeviceSTTEngine):
    def __init__(self, transcribed_text: str = "Voice test query"):
        super().__init__(is_on_device_verified=True)
        self.text = transcribed_text
        self.transcribe_called = False

    def transcribe(self, audio_data: bytes) -> str:
        self.transcribe_called = True
        return self.text


class CustomMockTTS(OnDeviceTTSEngine):
    def __init__(self):
        super().__init__(is_local_voice_verified=True)
        self.spoken_texts: List[str] = []

    def speak(self, text: str) -> Optional[str]:
        self.spoken_texts.append(text)
        return "LOCAL_AUDIO_PLAYBACK_OK"


class TestPhase3StageIE2EVerification(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ashwin_stage_i_e2e_")

        # Initialize Moto G3 Storage Server & Jail
        self.server = MotoStorageServer(root_dir=self.test_dir)
        self.moto_connector = MotoConnector(server=self.server)
        self.moto_connector.run_feasibility_gate(True, True, True)
        self.moto_connector.pair_device(True)

        # Create test documents in Moto server jail
        self.docs_dir = os.path.join(self.server.jail.canonical_root, "Documents")
        os.makedirs(self.docs_dir, exist_ok=True)

        self.doc_path = os.path.join(self.docs_dir, "resume.txt")
        with open(self.doc_path, "w", encoding="utf-8") as f:
            f.write("Candidate Resume: Senior Systems Security Engineer.")

        # Synthetic secret document for RULE-09 test
        self.secret_doc_path = os.path.join(self.docs_dir, "credentials.txt")
        self.synthetic_secret = "AIzaSyDummyTestKeyForScannerVerification12345"
        with open(self.secret_doc_path, "w", encoding="utf-8") as f:
            f.write(f"Cloud storage configuration api_key={self.synthetic_secret} for backup.")

        # Initialize Storage Adapter, Session, and Voice Subsystem
        self.storage_adapter = MotoStorageAdapter(self.moto_connector)
        self.session = CoreSession(storage_connector=self.storage_adapter)

        self.stt = CustomMockSTT("What is the status of my private storage?")
        self.tts = CustomMockTTS()
        self.voice_subsystem = VoiceSubsystem(
            session=self.session,
            stt_engine=self.stt,
            tts_engine=self.tts
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Typed Input Pipeline
    # -------------------------------------------------------------------------
    def test_e2e_typed_input_to_local_ai(self):
        """Pipeline 1: Typed input -> classification -> scan -> memory -> AIRouter -> Local AI."""
        res = self.session.execute_turn(
            raw_text="Plan my schedule for tomorrow morning",
            source=SourceDomain.PHONE,
            is_stt=False
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["is_local"])
        self.assertEqual(res["provider_used"], "LocalAI")

        # Verify Memory insertion
        items = self.session.memory_store._items
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].source, SourceDomain.PHONE)
        self.assertEqual(items[0].data_class, DataClass.PROTECTED)
        self.assertTrue(items[0].scanned)

    # -------------------------------------------------------------------------
    # 2. Voice Subsystem Pipeline
    # -------------------------------------------------------------------------
    def test_e2e_voice_transcription_to_tts_pipeline(self):
        """Pipeline 2: Voice input -> on-device STT -> classification -> scan -> memory -> AIRouter -> Local AI -> local TTS."""
        voice_res = self.voice_subsystem.process_voice_turn(b"dummy_audio_bytes")
        self.assertEqual(voice_res["status"], "SUCCESS")
        self.assertTrue(self.stt.transcribe_called)
        self.assertGreater(len(self.tts.spoken_texts), 0)
        self.assertTrue(voice_res["is_local"])

        # Check Memory state from voice turn
        items = self.session.memory_store._items
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].metadata.get("input_type"), "STT")
        self.assertEqual(items[0].data_class, DataClass.PROTECTED)

    # -------------------------------------------------------------------------
    # 3. Moto Storage Pipeline (Local AI)
    # -------------------------------------------------------------------------
    def test_e2e_moto_storage_to_local_ai(self):
        """Pipeline 3: Moto storage permission -> mTLS retrieval -> bounded buffering -> extraction -> secret scan/redaction -> PROTECTED classification -> memory -> AIRouter -> Local AI."""
        permission_prompted = []

        def allow_callback(prompt: str) -> bool:
            permission_prompted.append(prompt)
            return True

        res = self.session.execute_storage_turn(
            command_text="Read my resume from Moto storage",
            operation="read",
            target_path="Documents/resume.txt",
            permission_prompt_callback=allow_callback
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["is_local"])
        self.assertEqual(len(permission_prompted), 1)
        self.assertIn("Your private Moto storage requires permission. May I access it?", permission_prompted[0])

        # Verify separate contexts in memory
        items = self.session.memory_store._items
        self.assertEqual(len(items), 2)
        cmd_item = items[0]
        moto_item = items[1]

        self.assertEqual(cmd_item.source, SourceDomain.PHONE)
        self.assertEqual(moto_item.source, SourceDomain.MOTO_STORAGE)
        self.assertEqual(moto_item.data_class, DataClass.PROTECTED)
        self.assertIn("Candidate Resume", moto_item.content)
        self.assertEqual(moto_item.metadata["location_for_model"], "MOTO_STORAGE/resume.txt")

    # -------------------------------------------------------------------------
    # 4. Moto Storage to Cloud AI Consent Escalation
    # -------------------------------------------------------------------------
    def test_e2e_moto_storage_to_cloud_consent_flow(self):
        """Pipeline 4: Moto content -> per-request CloudConsentToken when Local AI is unavailable."""
        self.session.router.set_local_availability(False)
        self.storage_adapter.set_access_permission(True)

        coordinator = MockConsentCoordinator(grant=True)
        res = self.session.execute_storage_turn(
            command_text="Analyze resume with cloud model",
            operation="read",
            target_path="Documents/resume.txt",
            permission_prompt_callback=lambda p: True,
            consent_coordinator=coordinator
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["is_local"])
        self.assertEqual(coordinator.request_count, 1)

        # Verify minimal metadata (RULE: no raw content in consent request)
        self.assertIsNotNone(coordinator.captured_metadata)
        self.assertEqual(coordinator.captured_metadata.source_domain, SourceDomain.MOTO_STORAGE)
        self.assertEqual(coordinator.captured_metadata.data_class, DataClass.PROTECTED)
        self.assertNotIn("Candidate Resume", coordinator.captured_metadata.rationale)

        # Restore Local AI
        self.session.router.set_local_availability(True)

    # -------------------------------------------------------------------------
    # 5. Cloud Consent Denial Blocks Transmission
    # -------------------------------------------------------------------------
    def test_e2e_cloud_consent_denial_blocks_egress(self):
        """Pipeline 5: Cloud consent denial prevents egress and returns clean denial message."""
        self.session.router.set_local_availability(False)
        self.storage_adapter.set_access_permission(True)

        coordinator = MockConsentCoordinator(grant=False)
        res = self.session.execute_storage_turn(
            command_text="Analyze resume with cloud model",
            operation="read",
            target_path="Documents/resume.txt",
            permission_prompt_callback=lambda p: True,
            consent_coordinator=coordinator
        )

        self.assertEqual(res["status"], "DENIED")
        self.assertIn("denied by user", res["message"])

        # Restore Local AI
        self.session.router.set_local_availability(True)

    # -------------------------------------------------------------------------
    # 6. Early Hard Fail-Closed for HIGHLY_PROTECTED Input
    # -------------------------------------------------------------------------
    def test_e2e_highly_protected_early_hard_block(self):
        """Pipeline 6a: HIGHLY_PROTECTED/credential input is blocked before memory, consent, Router, or model ingress."""
        oversized_input = "SECRET_CREDENTIAL_DATA_" * 50_000

        with self.assertRaises((SecurityViolation, RouterGateError)):
            self.session.execute_turn(
                raw_text=oversized_input,
                source=SourceDomain.PHONE
            )

        # Assert zero memory insertion
        self.assertEqual(self.session.memory_store.count, 0)

    def test_e2e_scanner_unhealthy_causes_fail_closed(self):
        """Pipeline 6b: SecretScanner unhealthy/failure causes fail-closed behavior before model ingress."""
        self.session.scanner.set_health(False)

        with self.assertRaises(RouterGateError):
            self.session.execute_turn(
                raw_text="Ordinary query while scanner is broken",
                source=SourceDomain.PHONE
            )

        # Assert zero memory insertion
        self.assertEqual(self.session.memory_store.count, 0)
        self.session.scanner.set_health(True)

    # -------------------------------------------------------------------------
    # 7. Model Ingress Secret Redaction Boundary Assertion (RULE-09)
    # -------------------------------------------------------------------------
    def test_e2e_secret_redaction_before_model_ingress(self):
        """Pipeline 7: Synthetic secret is absent from ScannedClassifiedContext delivered to AIRouter/provider."""
        self.storage_adapter.set_access_permission(True)
        ctx = self.storage_adapter.read_file("Documents/credentials.txt")

        # Mandatory assertion: synthetic secret absent from ScannedClassifiedContext delivered to router
        self.assertNotIn(self.synthetic_secret, ctx.content)
        self.assertIn("[REDACTED:API_KEY]", ctx.content)

        # Verify delivery through AIRouter
        res = self.session.router.process_context(ctx)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertNotIn(self.synthetic_secret, res.get("response", ""))

    # -------------------------------------------------------------------------
    # 8. Single-Use and Binding Validation of CloudConsentToken
    # -------------------------------------------------------------------------
    def test_e2e_cloud_token_single_use_and_binding_validation(self):
        """Pipeline 8: Cloud consent is single-use and bound to exact request/provider/context."""
        token = CloudConsentToken(
            request_id="req-12345",
            source_domain=SourceDomain.MOTO_STORAGE,
            data_class=DataClass.PROTECTED,
            target_provider="CloudAI"
        )
        ctx = ScannedClassifiedContext(
            content="Protected storage content",
            data_class=DataClass.PROTECTED,
            source=SourceDomain.MOTO_STORAGE,
            scanned=True,
            scan_summary={"healthy": True}
        )

        self.session.router.set_local_availability(False)

        # First use succeeds and consumes token
        res1 = self.session.router.process_context(ctx, consent_token=token)
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertTrue(token.is_consumed)

        # Replay attempt fails closed with SecurityViolation
        with self.assertRaises(SecurityViolation):
            self.session.router.process_context(ctx, consent_token=token)

        # Restore Local AI
        self.session.router.set_local_availability(True)

    # -------------------------------------------------------------------------
    # 9. Session Reset and Termination Lifecycle Isolation
    # -------------------------------------------------------------------------
    def test_e2e_session_reset_and_termination_isolation(self):
        """Pipeline 9: Reset and termination clear transient memory and revoke Moto access permission."""
        self.storage_adapter.set_access_permission(True)
        self.session.execute_turn("Test query before reset", source=SourceDomain.PHONE)
        self.assertGreater(self.session.memory_store.count, 0)
        self.assertTrue(self.storage_adapter.get_access_permission())

        # Reset session
        old_id = self.session.session_id
        self.session.reset_session()
        self.assertNotEqual(self.session.session_id, old_id)
        self.assertEqual(self.session.memory_store.count, 0)
        self.assertFalse(self.storage_adapter.get_access_permission())

        # Terminate session
        self.storage_adapter.set_access_permission(True)
        self.session.terminate_session()
        self.assertFalse(self.session.is_active)
        self.assertEqual(self.session.memory_store.count, 0)
        self.assertFalse(self.storage_adapter.get_access_permission())

    # -------------------------------------------------------------------------
    # 10. Moto Offline Handling and Core Independence
    # -------------------------------------------------------------------------
    def test_e2e_moto_offline_independence(self):
        """Pipeline 10: Offline Moto returns canonical message while non-Moto turns operate normally."""
        self.moto_connector.paired = False

        storage_res = self.session.execute_storage_turn(
            command_text="Read offline document",
            operation="read",
            target_path="Documents/resume.txt",
            permission_prompt_callback=lambda p: True
        )
        self.assertEqual(storage_res["status"], "OFFLINE")
        self.assertEqual(storage_res["message"], "Your private storage server is currently unavailable.")

        # Non-Moto turn operates normally
        core_res = self.session.execute_turn("Calculate 128 / 4", source=SourceDomain.PHONE)
        self.assertEqual(core_res["status"], "SUCCESS")
        self.assertTrue(core_res["is_local"])

    # -------------------------------------------------------------------------
    # 11. Explicit Router-Boundary Typing Assertion Across All Sources
    # -------------------------------------------------------------------------
    def test_e2e_router_boundary_typing_enforcement(self):
        """Pipeline 11: AIRouter accepts strictly typed ScannedClassifiedContext across typed, voice, and Moto sources."""
        # 1. Typed input generates ScannedClassifiedContext
        typed_ctx = self.session.classifier.process_user_input("Typed prompt", source=SourceDomain.PHONE)
        self.assertIsInstance(typed_ctx, ScannedClassifiedContext)
        res_typed = self.session.router.process_context(typed_ctx)
        self.assertEqual(res_typed["status"], "SUCCESS")

        # 2. Voice input generates ScannedClassifiedContext
        voice_ctx = self.session.classifier.process_user_input("Voice prompt", source=SourceDomain.PHONE, is_stt=True)
        self.assertIsInstance(voice_ctx, ScannedClassifiedContext)
        res_voice = self.session.router.process_context(voice_ctx)
        self.assertEqual(res_voice["status"], "SUCCESS")

        # 3. Moto input generates ScannedClassifiedContext
        self.moto_connector.paired = True
        self.storage_adapter.set_access_permission(True)
        moto_ctx = self.storage_adapter.read_file("Documents/resume.txt")
        self.assertIsInstance(moto_ctx, ScannedClassifiedContext)
        res_moto = self.session.router.process_context(moto_ctx)
        self.assertEqual(res_moto["status"], "SUCCESS")

        # 4. Raw string or unvalidated context rejected by router gate (RULE-04)
        with self.assertRaises(RouterGateError):
            self.session.router.process_context("raw_unclassified_string")  # type: ignore

    # -------------------------------------------------------------------------
    # 12. Model Context Secret & Credential Leakage Audit
    # -------------------------------------------------------------------------
    def test_e2e_ai_facing_interfaces_free_of_secrets(self):
        """Pipeline 12: Asserts zero leakage of keys, nonces, certificates, or session secrets in model context."""
        self.storage_adapter.set_access_permission(True)
        ctx = self.storage_adapter.read_file("Documents/credentials.txt")

        forbidden_tokens = [
            self.synthetic_secret,
            "X-Moto-Nonce",
            "X-Moto-Signature",
            "ASHWIN_MOTO_MTLS_SECRET",
            "BEGIN PRIVATE KEY",
            "C:\\",
            "/sdcard/"
        ]

        for token in forbidden_tokens:
            self.assertNotIn(token, ctx.content)
            self.assertNotIn(token, json.dumps(ctx.metadata))


if __name__ == "__main__":
    unittest.main()
