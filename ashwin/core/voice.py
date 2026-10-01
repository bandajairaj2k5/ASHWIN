"""
ASHWIN Voice Subsystem (Phase 3 / Stage F, Section 2.7, Section 11, RULE-01, RULE-02, RULE-11).
Pipeline: Microphone / Audio -> On-Device STT -> InputClassifier -> EphemeralMemoryStore -> AIRouter -> LocalAI -> On-Device TTS.
Bound strictly to CoreSession security components.
"""

from typing import Dict, Any, Tuple, Optional
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
from ashwin.core.router import AIRouter


class OnDeviceSTTEngine:
    """
    On-device Speech-to-Text abstraction enforcing RULE-11.
    Fails closed if on-device execution cannot be verified.
    """

    def __init__(self, is_on_device_verified: bool = True):
        self.is_on_device_verified = is_on_device_verified

    def set_on_device_verified(self, verified: bool):
        self.is_on_device_verified = verified

    def transcribe(self, audio_bytes: bytes) -> str:
        """
        Transcribes audio bytes into text.
        Fails closed if on-device STT cannot be verified.
        """
        if not self.is_on_device_verified:
            raise SecurityViolation(
                "RULE-11 Violation: On-device STT is unverified. Voice input unavailable. Please use typed input."
            )
        # On-device simulated / model inference
        return "Transcribed on-device voice utterance."


class OnDeviceTTSEngine:
    """
    On-device Text-to-Speech abstraction (Section 2.7).
    Fails closed to text-only if local voice is unavailable or requires network.
    """

    def __init__(self, is_local_voice_verified: bool = True):
        self.is_local_voice_verified = is_local_voice_verified

    def set_local_voice_verified(self, verified: bool):
        self.is_local_voice_verified = verified

    def speak(self, text: str) -> Optional[str]:
        """
        Synthesizes speech on-device.
        Returns synthesized audio description or None if local voice unavailable.
        """
        if not self.is_local_voice_verified:
            return None  # Fail closed to text-only delivery
        return f"[Synthesized Audio (Local Voice)]: {text}"


class VoiceSubsystem:
    """
    Coordinates Voice Interface baseline bound to CoreSession:
    Audio -> OnDeviceSTTEngine -> CoreSession.classifier -> CoreSession.memory_store -> CoreSession.router -> OnDeviceTTSEngine
    """

    def __init__(
        self,
        session: Optional[CoreSession] = None,
        stt_engine: Optional[OnDeviceSTTEngine] = None,
        tts_engine: Optional[OnDeviceTTSEngine] = None
    ):
        self.session = session or CoreSession()
        self.stt_engine = stt_engine or OnDeviceSTTEngine(is_on_device_verified=True)
        self.tts_engine = tts_engine or OnDeviceTTSEngine(is_local_voice_verified=True)
        self.is_active = True

    @property
    def scanner(self) -> SecretScanner:
        return self.session.scanner

    @property
    def classifier(self) -> InputClassifier:
        return self.session.classifier

    @property
    def memory_store(self) -> EphemeralMemoryStore:
        return self.session.memory_store

    @property
    def router(self) -> AIRouter:
        return self.session.router

    def process_voice_turn(
        self,
        audio_bytes: bytes,
        user_cloud_consent: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a full voice turn under security invariants:
        1. On-device STT transcription.
        2. InputClassifier classification (PROTECTED by default, RULE-01).
        3. SecretScanner pattern redaction.
        4. CoreSession memory_store insertion (transient RAM only, no audio persisted).
        5. AIRouter model invocation (LocalAI by default).
        6. On-device TTS synthesis (fails closed to text-only).
        """
        if not self.is_active or not self.session.is_active:
            raise SecurityViolation("VoiceSubsystem is inactive or CoreSession is inactive.")

        # Step 1: On-device STT (Fails closed if unverified per RULE-11)
        try:
            raw_transcription = self.stt_engine.transcribe(audio_bytes)
        except SecurityViolation as e:
            return {
                "status": "STT_UNAVAILABLE",
                "error": str(e),
                "message": "On-device speech recognition is unavailable. Please use typed input."
            }

        # Step 2 & 3: InputClassifier ingestion (Assigns PROTECTED by default, runs SecretScanner)
        classified_context = self.classifier.process_user_input(
            raw_text=raw_transcription,
            source=SourceDomain.PHONE,
            is_stt=True
        )

        # Step 4: Ephemeral RAM memory insertion (uses CoreSession-owned memoryStore)
        self.session.memory_store.add_context(classified_context)

        # Step 5: Route through AIRouter (Sole model delivery boundary)
        router_result = self.router.process_context(
            context=classified_context,
            user_cloud_consent=user_cloud_consent
        )

        if router_result.get("status") != "SUCCESS":
            return {
                "status": router_result.get("status"),
                "reason": router_result.get("reason"),
                "user_prompt_required": router_result.get("user_prompt_required", False),
                "transcription": classified_context.content,
                "message": router_result.get("message")
            }

        response_text = router_result.get("response", "")

        # Step 6: On-device TTS synthesis
        tts_output = self.tts_engine.speak(response_text)

        return {
            "status": "SUCCESS",
            "transcription": classified_context.content,
            "data_class": classified_context.data_class.value,
            "provider_used": router_result.get("provider_used"),
            "is_local": router_result.get("is_local"),
            "response": response_text,
            "audio_synthesized": tts_output is not None,
            "tts_output": tts_output
        }

    def process_voice_input(
        self,
        audio_bytes: bytes,
        use_cloud_stt: bool = False,
        cloud_stt_consent: bool = False
    ) -> Tuple[ScannedClassifiedContext, Optional[str]]:
        """
        Legacy/T-35 interface for voice input processing enforcing RULE-02 cloud consent and RULE-11 on-device STT.
        """
        if use_cloud_stt:
            if not cloud_stt_consent:
                raise SecurityViolation(
                    "RULE-02 Violation: Cloud STT requires explicit per-request consent. "
                    "Raw audio cannot leave device."
                )
            transcription = "[Cloud STT Transcription]: " + f"Audio length {len(audio_bytes)} bytes"
        else:
            if not self.stt_engine.is_on_device_verified:
                return None, "On-device STT cannot be verified. Voice input is unavailable. Please use typed input."
            transcription = self.stt_engine.transcribe(audio_bytes)

        classified_context = self.classifier.process_user_input(
            raw_text=transcription,
            source=SourceDomain.PHONE,
            is_stt=True
        )
        return classified_context, None

    def reset(self):
        """Cleans up any transient voice state."""
        self.session.memory_store.clear()

    def terminate(self):
        self.is_active = False
        self.reset()
