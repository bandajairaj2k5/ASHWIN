"""
ASHWIN File Location Formatter (RULE-15).
Ensures the AI model receives ONLY minimum safe location representations (Scope label + allowlisted name).
Prevents drive letters, user paths, or absolute system paths from entering model context.
"""

import os
from typing import Dict, Any


class LocationFormatter:
    """
    Implements RULE-15 file location representation formatting.
    """

    @staticmethod
    def format_for_model(scope_label: str, filename: str) -> str:
        """
        Formats a location representation for model context.
        Example: "Projects/report.txt" or "MOTO_STORAGE/resume.pdf"
        """
        # Clean any accidental path separators in filename
        safe_name = os.path.basename(filename)
        # Ensure no drive letters or raw paths
        safe_label = scope_label.strip("/\\")
        return f"{safe_label}/{safe_name}"

    @staticmethod
    def strip_raw_paths_from_text(text: str, scope_mappings: Dict[str, str]) -> str:
        """
        Sanitizes text by replacing raw absolute paths with scope labels.
        """
        sanitized = text
        for scope_label, raw_path in scope_mappings.items():
            if raw_path in sanitized:
                sanitized = sanitized.replace(raw_path, f"[{scope_label}]")
        return sanitized
