"""
Unit tests for Phase 3 / Stage F: Voice Interface Baseline.
Verifies the complete pipeline, CoreSession component binding, fail-closed STT, fail-closed TTS, secret scanning, classification, memory, and AIRouter boundaries.
"""

import unittest
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.session import CoreSession
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.classifier import InputClassifier
from ashwin.core.memory import EphemeralMemoryStore
from ashwin.core.router import AIRouter, LocalAIProvider, CloudAIProvider
from ashwin.core.voice import (
    VoiceSubsystem,
    OnDeviceSTTEngine,
    OnDeviceTTSEngine,
)


class MockCustomSTTEngine(OnDeviceSTTEngine):
    def __init__(self, transcript: str = "Voice query text", is_on_device_verified: bool = True):
        super().__init__(is_on_device_verified=is_on_device_verified)
        self.transcript = transcript

    def transcribe(self, audio_bytes: bytes) -> str:
        if not self.is_on_device_verified:
            raise SecurityViolation("RULE-11 Violation: On-device STT unverified.")
        return self.transcript


class TestPhase3StageFVoice(unittest.TestCase):

    def setUp(self):
        self.session = CoreSession()
        self.stt = MockCustomSTTEngine(transcript="What is my schedule for today?")
        self.tts = OnDeviceTTSEngine(is_local_voice_verified=True)
        self.voice = VoiceSubsystem(
            session=self.session,
            stt_engine=self.stt,
            tts_engine=self.tts
        )

    def test_voice_pipeline_success_and_core_session_binding(self):
        """End-to-end voice turn executes on-device and populates CoreSession memory directly."""
        res = self.voice.process_voice_turn(audio_bytes=b"\x00\x01\x02\x03")

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["transcription"], "What is my schedule for today?")
        self.assertEqual(res["data_class"], DataClass.PROTECTED.value)
        self.assertEqual(res["provider_used"], "LocalAI")
        self.assertTrue(res["is_local"])
        self.assertTrue(res["audio_synthesized"])
        self.assertIsNotNone(res["tts_output"])

        # Check CoreSession's memory was updated directly (shared memory store)
        self.assertEqual(self.session.memory_store.count, 1)
        self.assertIn("What is my schedule for today?", self.session.memory_store.get_items()[0].content)

    def test_core_session_lifecycle_clears_voice_memory(self):
        """Resetting CoreSession clears voice conversation memory."""
        self.voice.process_voice_turn(audio_bytes=b"\x00\x01")
        self.assertEqual(self.session.memory_store.count, 1)

        self.session.reset_session()
        self.assertEqual(self.session.memory_store.count, 0)

        self.voice.process_voice_turn(audio_bytes=b"\x00\x02")
        self.assertEqual(self.session.memory_store.count, 1)

        self.session.terminate_session()
        self.assertEqual(self.session.memory_store.count, 0)
        self.assertFalse(self.session.is_active)

        # Inactive session rejects new voice turns
        with self.assertRaises(SecurityViolation):
            self.voice.process_voice_turn(audio_bytes=b"\x00\x03")

    def test_unverified_stt_fails_closed_and_offers_typed_input(self):
        """RULE-11: If on-device STT cannot be verified, fail closed and offer typed input."""
        self.stt.set_on_device_verified(False)
        res = self.voice.process_voice_turn(audio_bytes=b"\x00\x01")

        self.assertEqual(res["status"], "STT_UNAVAILABLE")
        self.assertIn("typed input", res["message"].lower())
        self.assertEqual(self.session.memory_store.count, 0)

    def test_stt_output_classified_protected_by_default(self):
        """RULE-01 / Section 4.2: Voice STT output is classified PROTECTED by default."""
        res = self.voice.process_voice_turn(audio_bytes=b"dummy")
        self.assertEqual(res["data_class"], DataClass.PROTECTED.value)

    def test_secret_redaction_in_stt_transcription(self):
        """RULE-09 / RULE-10: Detected secrets in voice transcription are redacted before model ingress."""
        secret_stt = MockCustomSTTEngine(transcript="My key is sk-1234567890abcdef123456 please keep it.")
        voice_with_secret = VoiceSubsystem(
            session=self.session,
            stt_engine=secret_stt,
            tts_engine=self.tts
        )
        res = voice_with_secret.process_voice_turn(audio_bytes=b"dummy")

        self.assertEqual(res["status"], "SUCCESS")
        self.assertNotIn("sk-1234567890abcdef123456", res["transcription"])
        self.assertIn("[REDACTED:API_KEY]", res["transcription"])

    def test_local_ai_unavailable_denies_voice_without_cloud_consent(self):
        """Section 4.5: If Local AI is down, voice context is NOT sent to cloud AI without consent."""
        self.session.router.set_local_availability(False)
        res = self.voice.process_voice_turn(audio_bytes=b"dummy", user_cloud_consent=False)

        self.assertEqual(res["status"], "DENIED")
        self.assertTrue(res["user_prompt_required"])

    def test_unverified_tts_fails_closed_to_text_only(self):
        """If on-device TTS is unverified or requires network, deliver text-only response."""
        self.tts.set_local_voice_verified(False)
        res = self.voice.process_voice_turn(audio_bytes=b"dummy")

        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["audio_synthesized"])
        self.assertIsNone(res["tts_output"])
        self.assertTrue(len(res["response"]) > 0)


if __name__ == "__main__":
    unittest.main()
