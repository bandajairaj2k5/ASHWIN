"""
ASHWIN Secret Scanner (RULE-09, RULE-10).
Detects and redacts credentials, keys, tokens, cookies, recovery codes, connection strings.
Enforces redact-or-withhold and fail-closed handling.
"""

import re
import time
from typing import Dict, Any, Tuple, Optional
from ashwin.core.models import DataClass


class SecretScanner:
    """
    Secret Scanner enforcing RULE-09 & RULE-10.
    """
    def __init__(self, healthy: bool = True):
        self._healthy = healthy
        self._patterns = [
            # Private keys
            (r'-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----', 'PRIVATE_KEY'),
            (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----', 'PRIVATE_KEY'),
            # Known API keys (OpenAI sk-..., AWS AKIA..., GitHub ghp_..., etc.)
            (r'(sk-[a-zA-Z0-9]{16,})', 'API_KEY'),
            (r'(AKIA[0-9A-Z]{16})', 'API_KEY'),
            (r'(ghp_[a-zA-Z0-9]{36})', 'API_KEY'),
            (r'(glpat-[a-zA-Z0-9\-]{20,})', 'API_KEY'),
            # Generic High-Entropy API key patterns
            (r'(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'API_KEY'),
            # Passwords in config/assignments
            (r'(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', 'PASSWORD'),
            # JWT and Bearer tokens
            (r'(bearer\s+eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', 'OAUTH_TOKEN'),
            (r'(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', 'OAUTH_TOKEN'),
            # Session Cookies
            (r'(session[_\-]?id|PHPSESSID|JSESSIONID)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'SESSION_COOKIE'),
            # Connection strings with credentials
            (r'([a-zA-Z0-9]+://[a-zA-Z0-9_%]+:[^@\s]+@[a-zA-Z0-9_%\.\-]+:[0-9]+/[a-zA-Z0-9_%]+)', 'CONNECTION_STRING'),
            # Recovery / Backup codes
            (r'([0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4})', 'RECOVERY_CODE'),
        ]

    def set_health(self, healthy: bool):
        self._healthy = healthy

    def is_healthy(self) -> bool:
        return self._healthy

    def scan_and_redact(
        self,
        text: str,
        timeout_sec: float = 5.0,
        max_length: int = 1_000_000
    ) -> Tuple[str, Dict[str, Any], DataClass]:
        """
        Scans and redacts secret material from text.
        """
        start_time = time.time()
        
        if not self._healthy:
            return text, {
                "healthy": False,
                "error": "Scanner unavailable or unhealthy",
                "redaction_count": 0,
                "redactions": {}
            }, DataClass.HIGHLY_PROTECTED

        if text is None:
            text = ""

        if len(text) > max_length:
            return text, {
                "healthy": False,
                "error": f"Input size {len(text)} exceeds max scannable size {max_length}",
                "redaction_count": 0,
                "redactions": {}
            }, DataClass.HIGHLY_PROTECTED

        redacted_text = text
        redactions: Dict[str, int] = {}
        total_redactions = 0

        for pattern, secret_type in self._patterns:
            if time.time() - start_time > timeout_sec:
                return text, {
                    "healthy": False,
                    "error": "Scanner timed out during regex evaluation",
                    "redaction_count": 0,
                    "redactions": {}
                }, DataClass.HIGHLY_PROTECTED

            def replace_fn(match: re.Match) -> str:
                nonlocal total_redactions
                total_redactions += 1
                redactions[secret_type] = redactions.get(secret_type, 0) + 1
                return f"[REDACTED:{secret_type}]"

            redacted_text = re.sub(pattern, replace_fn, redacted_text, flags=re.IGNORECASE)

        scan_summary = {
            "healthy": True,
            "redaction_count": total_redactions,
            "redactions": redactions,
            "scan_duration_ms": round((time.time() - start_time) * 1000, 2)
        }

        return redacted_text, scan_summary, DataClass.PROTECTED
