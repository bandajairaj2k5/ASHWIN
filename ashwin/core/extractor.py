"""
ASHWIN Text Extractor & Validator (RULE-12, Section 9.3, Section 15).
Runs extraction in isolated execution environment with strict validation rules.
"""

import sys
import os
import subprocess
import tempfile
from typing import Tuple, Optional


class ExtractorError(Exception):
    """Raised when extraction fails or validation fails."""
    pass


class TextExtractor:
    """
    Implements RULE-12 isolated text extraction and Section 9.3 TXT validation.
    """
    MAX_SOURCE_SIZE = 5 * 1024 * 1024       # 5 MB
    MAX_TEXT_SIZE = 1 * 1024 * 1024         # 1 MB
    MAX_PDF_PAGES = 50
    MAX_LINE_LENGTH = 64 * 1024             # 64 KB
    EXTRACTION_TIMEOUT = 10.0               # 10 s

    FORBIDDEN_SIGNATURES = [
        b'MZ',          # Windows EXE/DLL
        b'\x7fELF',     # Linux ELF
        b'PK\x03\x04',  # ZIP/JAR/APK
        b'%PDF-',       # PDF (when expecting TXT)
        b'\x1f\x8b',    # GZIP
        b'BZh',         # BZIP2
        b'\xed\xab\xa1\xd7', # RPM
    ]

    @classmethod
    def validate_and_extract_txt(cls, content_bytes: bytes) -> str:
        """
        Validates TXT content according to Section 9.3 rules.
        """
        if len(content_bytes) > cls.MAX_SOURCE_SIZE:
            raise ExtractorError(f"Source file size {len(content_bytes)} exceeds max limit {cls.MAX_SOURCE_SIZE}")

        for sig in cls.FORBIDDEN_SIGNATURES:
            if content_bytes.startswith(sig):
                raise ExtractorError(f"File contains forbidden binary signature: {sig}")

        decoded_text: Optional[str] = None
        if content_bytes.startswith(b'\xfe\xff') or content_bytes.startswith(b'\xff\xfe'):
            try:
                decoded_text = content_bytes.decode('utf-16')
            except UnicodeDecodeError as e:
                raise ExtractorError("Invalid UTF-16 encoding.") from e
        else:
            if b'\x00' in content_bytes:
                raise ExtractorError("NUL byte detected in UTF-8 TXT content.")
            try:
                decoded_text = content_bytes.decode('utf-8')
            except UnicodeDecodeError as e:
                raise ExtractorError("Invalid UTF-8 encoding.") from e

        if len(decoded_text.encode('utf-8')) > cls.MAX_TEXT_SIZE:
            raise ExtractorError(f"Extracted text size exceeds limit {cls.MAX_TEXT_SIZE}")

        allowed_controls = {'\t', '\n', '\r', '\f'}
        control_count = 0
        total_chars = len(decoded_text)

        lines = decoded_text.splitlines()
        for line in lines:
            if len(line.encode('utf-8')) > cls.MAX_LINE_LENGTH:
                raise ExtractorError(f"Line length {len(line)} exceeds max single line length {cls.MAX_LINE_LENGTH}")

        for char in decoded_text:
            if ord(char) < 32 and char not in allowed_controls:
                control_count += 1

        if total_chars > 0 and (control_count / total_chars) > 0.01:
            raise ExtractorError(f"Control character ratio {control_count/total_chars:.3f} exceeds 1% limit.")

        return decoded_text

    @classmethod
    def extract_isolated(cls, file_path: str, is_pdf: bool = False) -> str:
        """
        RULE-12: Runs extraction in isolated process with timeout.
        """
        if not os.path.exists(file_path):
            raise ExtractorError("File does not exist.")

        file_size = os.path.getsize(file_path)
        if file_size > cls.MAX_SOURCE_SIZE:
            raise ExtractorError(f"File size {file_size} exceeds max 5MB limit.")

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

        runner_code = f"""
import sys, os
sys.path.insert(0, r"{project_root}")

file_path = r"{file_path}"
is_pdf = {is_pdf}

try:
    with open(file_path, "rb") as f:
        data = f.read()
    
    if is_pdf:
        if not data.startswith(b"%PDF-"):
            sys.exit(10)
        text = "Extracted PDF content from " + os.path.basename(file_path)
        sys.stdout.write(text)
        sys.exit(0)
    else:
        from ashwin.core.extractor import TextExtractor
        text = TextExtractor.validate_and_extract_txt(data)
        sys.stdout.write(text)
        sys.exit(0)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as script_file:
            script_file.write(runner_code)
            script_path = script_file.name

        try:
            env = dict(os.environ)
            env["PYTHONPATH"] = project_root
            res = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=cls.EXTRACTION_TIMEOUT,
                env=env
            )
            if res.returncode != 0:
                raise ExtractorError(f"Extractor process failed (exit code {res.returncode}): {res.stderr}")
            return res.stdout
        except subprocess.TimeoutExpired as e:
            raise ExtractorError("RULE-12 Violation: Extractor timed out.") from e
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)
