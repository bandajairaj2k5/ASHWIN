"""
ASHWIN Voice & Speech-To-Text Subsystem (RULE-11, RULE-02, RULE-01).
Enforces on-device STT verification and per-request cloud STT consent.
"""

from typing import Dict, Any, Tuple, Optional
from ashwin.core.models import DataClass, SourceDomain, ScannedClassifiedContext, SecurityViolation
from ashwin.core.secret_scanner import SecretScanner


class VoiceSubsystem:
    """
    Implements RULE-11 on-device STT verification and RULE-02 Cloud STT consent.
    """

    def __init__(self, scanner: Optional[SecretScanner] = None):
        self.scanner = scanner or SecretScanner()
        self._on_device_stt_verified = True
        self._cloud_stt_enabled = False

    def verify_on_device_stt(self, network_blocked_test_passed: bool) -> bool:
        """
        RULE-11: Verifies that STT runs in a module with network access blocked.
        """
        self._on_device_stt_verified = network_blocked_test_passed
        return self._on_device_stt_verified

    def process_voice_input(
        self,
        audio_bytes: bytes,
        use_cloud_stt: bool = False,
        cloud_stt_consent: bool = False
    ) -> Tuple[ScannedClassifiedContext, Optional[str]]:
        """
        Processes audio input into transcribed text and wraps in ScannedClassifiedContext.
        """
        if use_cloud_stt:
            # RULE-02: Cloud STT requires separate explicit per-request consent
            if not self._cloud_stt_enabled or not cloud_stt_consent:
                raise SecurityViolation(
                    "RULE-02 Violation: Cloud STT requires explicit per-request consent. "
                    "Raw audio cannot leave device."
                )
            transcription = "[Cloud STT Transcription]: " + f"Audio length {len(audio_bytes)} bytes"
        else:
            # RULE-11: Must be verifiably on-device
            if not self._on_device_stt_verified:
                return None, "On-device STT cannot be verified. Voice input is unavailable. Please use typed input."
            transcription = "Simulated on-device transcribed text from audio input."

        # RULE-01 / Section 9.6: STT output is classified PROTECTED by default & scanned
        redacted_text, scan_summary, _ = self.scanner.scan_and_redact(transcription)

        warning_msg = None
        if scan_summary.get("redaction_count", 0) > 0:
            warning_msg = "Warning: Sensitive credentials were detected in STT transcription and redacted."

        context = ScannedClassifiedContext(
            content=redacted_text,
            data_class=DataClass.PROTECTED,
            source=SourceDomain.PHONE,
            cloud_approved=False,
            scanned=True,
            scan_summary=scan_summary,
            metadata={"source_type": "voice_stt"}
        )

        return context, warning_msg
