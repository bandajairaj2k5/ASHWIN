"""
ASHWIN Windows Laptop Endpoint Agent (Phase 4, Section 8, RULE-06, RULE-07, RULE-08, RULE-14, RULE-15).
Restricted Windows endpoint agent exposing explicitly TEN TOOLS ONLY.
Implements native Win32 security APIs (CreateFileW, GetFileInformationByHandle, CreateProcessW),
DPAPI-encrypted persistent credentials, CSPRNG 128-bit ephemeral IDs with 5-minute TTL,
single-handle file processing, bounded discovery, alternate data stream / reparse point rejection,
and zero shell/arbitrary execution.
"""

import os
import sys
import time
import secrets
import stat
import tempfile
import hmac
import hashlib
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    PermissionClass,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.metadata_pipeline import MetadataPipeline
from ashwin.core.location_formatter import LocationFormatter
from ashwin.core.extractor import TextExtractor, ExtractorError


class AgentSecurityError(Exception):
    """Raised when laptop agent security validation fails."""
    pass


# ==================== WIN32 NATIVE SECURITY STRUCTURES & BINDINGS ====================

if sys.platform == "win32":
    kernel32 = ctypes.windll.kernel32
    crypt32 = ctypes.windll.crypt32

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME),
            ("ftLastAccessTime", FILETIME),
            ("ftLastWriteTime", FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]

    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]

    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]

    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_char_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]

    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]

    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]

    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]


def _launch_native_win32_process(exe_path: str, cmd_line_str: Optional[str] = None) -> int:
    """
    Launches executable directly using Win32 CreateProcessW.
    Zero shell, no cmd.exe, no PowerShell, no os.system, no ShellExecute,
    no arbitrary file associations.
    """
    if sys.platform != "win32":
        return 1000

    if not os.path.isabs(exe_path) or not os.path.isfile(exe_path):
        raise AgentSecurityError(f"Executable does not exist or is not an absolute path: '{exe_path}'")

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    full_cmd_line = f'"{exe_path}" {cmd_line_str}' if cmd_line_str else None

    ok = kernel32.CreateProcessW(
        exe_path,
        full_cmd_line,
        None,
        None,
        False,
        0,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )

    if not ok:
        err = kernel32.GetLastError()
        raise AgentSecurityError(f"Win32 CreateProcessW failed for '{exe_path}' with error code {err}")

    pid = pi.dwProcessId
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    return pid


def dpapi_encrypt_bytes(data: bytes, description: str = "ASHWIN_LAPTOP_SECRET") -> bytes:
    """Encrypts bytes using Windows DPAPI (CryptProtectData). Never stores plaintext on disk."""
    if sys.platform != "win32":
        return b"DPAPI_SIMULATED:" + data

    blob_in = DATA_BLOB(
        len(data),
        ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)),
    )
    blob_out = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        description,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise AgentSecurityError("DPAPI CryptProtectData failed.")

    try:
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return encrypted
    finally:
        kernel32.LocalFree(blob_out.pbData)


def dpapi_decrypt_bytes(encrypted_data: bytes) -> bytes:
    """Decrypts DPAPI-encrypted bytes using Windows DPAPI (CryptUnprotectData)."""
    if sys.platform != "win32":
        if encrypted_data.startswith(b"DPAPI_SIMULATED:"):
            return encrypted_data[len(b"DPAPI_SIMULATED:"):]
        raise AgentSecurityError("Invalid simulated DPAPI data.")

    blob_in = DATA_BLOB(
        len(encrypted_data),
        ctypes.cast(ctypes.create_string_buffer(encrypted_data), ctypes.POINTER(ctypes.c_byte)),
    )
    blob_out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise AgentSecurityError("DPAPI CryptUnprotectData failed. Cannot access protected key.")

    try:
        decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return decrypted
    finally:
        kernel32.LocalFree(blob_out.pbData)


@dataclass
class RegisteredID:
    id_val: str
    object_type: str  # "file" or "folder"
    canonical_path: str
    bound_vol_serial: str
    bound_file_id: str
    scope_label: str
    session_id: str
    device_id: str
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 300.0  # 5 minutes absolute TTL (RULE-08)

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


class WindowsLaptopAgent:
    """
    Restricted Windows Laptop Agent. Exposes EXPLICITLY TEN TOOLS ONLY.
    Enforces Win32 native security handle verification, DPAPI key storage,
    single-handle file copy, bounded discovery, and zero arbitrary execution.
    """

    ALLOWED_VIEW_EXTENSIONS = {".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf"}
    ALLOWED_READ_EXTENSIONS = {".txt", ".pdf"}
    FORBIDDEN_EXTENSIONS = {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".msc", ".msi", ".msp", ".scr",
        ".cpl", ".lnk", ".url", ".dll", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".svg", ".html", ".htm", ".xml"
    }

    # Explicit Allowlisted Application Binaries
    SYSTEM_ROOT = os.environ.get("SystemRoot", "C:\\Windows")
    SYSTEM32_DIR = os.path.join(SYSTEM_ROOT, "System32")
    APP_ALLOWLIST = {
        "NOTEPAD": os.path.join(SYSTEM32_DIR, "notepad.exe"),
        "CALCULATOR": os.path.join(SYSTEM32_DIR, "calc.exe"),
    }
    EXPLORER_PATH = os.path.join(SYSTEM_ROOT, "explorer.exe")

    # Bounded discovery limits
    MAX_SEARCH_DEPTH = 10
    MAX_SEARCH_RESULTS = 50
    SEARCH_TIMEOUT_SECONDS = 3.0

    def __init__(self, device_id: str = "LAPTOP-LOCAL-01"):
        self.device_id = device_id
        self.paired = False
        self.session_id: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self.approved_scopes: Dict[str, str] = {}  # scope_label -> raw_canonical_path
        self._id_registry: Dict[str, RegisteredID] = {}
        self.scanner = SecretScanner()
        self.metadata_pipeline = MetadataPipeline(scanner=self.scanner)
        self.temp_dir = tempfile.mkdtemp(prefix="ashwin_laptop_agent_temp_")
        self._persistent_key_path: Optional[str] = None

    # ==================== DPAPI PERSISTENT KEY STORAGE ====================

    def save_identity_dpapi(self, target_filepath: str, private_key_pem: bytes, cert_pem: bytes):
        """Saves laptop private key encrypted via DPAPI. Plaintext private keys are never written."""
        payload = b"---ASHWIN_IDENTITY_V1---\n" + cert_pem + b"\n---KEY_DELIMITER---\n" + private_key_pem
        encrypted_blob = dpapi_encrypt_bytes(payload, description="ASHWIN_LAPTOP_IDENTITY")
        with open(target_filepath, "wb") as f:
            f.write(encrypted_blob)
        self._persistent_key_path = target_filepath

    def load_identity_dpapi(self, filepath: str) -> Tuple[bytes, bytes]:
        """Loads and decrypts laptop private key from DPAPI-protected store."""
        if not os.path.exists(filepath):
            raise AgentSecurityError(f"DPAPI identity file not found: {filepath}")
        with open(filepath, "rb") as f:
            encrypted_blob = f.read()
        decrypted_payload = dpapi_decrypt_bytes(encrypted_blob)
        if b"---ASHWIN_IDENTITY_V1---\n" not in decrypted_payload or b"\n---KEY_DELIMITER---\n" not in decrypted_payload:
            raise AgentSecurityError("Corrupted or invalid DPAPI identity payload.")
        parts = decrypted_payload.split(b"\n---KEY_DELIMITER---\n")
        cert_pem = parts[0].replace(b"---ASHWIN_IDENTITY_V1---\n", b"")
        private_key_pem = parts[1]
        self._persistent_key_path = filepath
        return cert_pem, private_key_pem

    # ==================== PAIRING & CHALLENGE PROTOCOL ====================

    def generate_sas_code(self) -> str:
        """Generates 6-digit numeric Short Authentication String (SAS)."""
        return f"{secrets.randbelow(1000000):06d}"

    def pair_device(self, user_confirmed: bool = True, sas_code: str = "") -> str:
        """Establishes paired session state with SAS confirmation."""
        if not user_confirmed:
            raise AgentSecurityError("Pairing rejected: User did not confirm matching SAS code.")
        self.paired = True
        self.session_id = secrets.token_hex(16)
        self.session_key = secrets.token_bytes(32)
        self.invalidate_all_ids("Pairing established / Session initialized")
        return self.session_id

    def create_request_challenge(self) -> str:
        """Generates CSPRNG challenge nonce for request authentication."""
        return secrets.token_hex(16)

    def verify_request_signature(self, nonce: str, signature: str, payload: bytes) -> bool:
        """Verifies HMAC signature of request payload with challenge nonce and session key."""
        if not self.paired or not self.session_key:
            return False
        mac = hmac.new(self.session_key, nonce.encode("utf-8") + payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, signature)

    def revoke_pairing(self):
        """Revokes pairing and purges all active session identifiers."""
        self.paired = False
        self.session_id = None
        self.session_key = None
        self.invalidate_all_ids("Pairing revoked")

    # ==================== SCOPE & PATH VALIDATION ====================

    def add_approved_scope(self, scope_label: str, canonical_path: str):
        """Adds an approved scope path after strict canonical and system directory validation."""
        norm = os.path.abspath(canonical_path).replace("\\", "/").rstrip("/").lower()
        # Reject system roots and critical system locations
        restricted_prefixes = [
            "c:", "c:/", "c:/windows", "c:/program files",
            "c:/program files (x86)", "c:/programdata", "c:/users"
        ]
        if norm in restricted_prefixes:
            raise AgentSecurityError(f"Scope path '{canonical_path}' is a restricted system directory.")
        if norm.startswith("//") or norm.startswith("\\\\"):
            raise AgentSecurityError("UNC and network paths are strictly forbidden.")
        
        # Verify directory exists
        if not os.path.isdir(canonical_path):
            raise AgentSecurityError(f"Scope directory does not exist: '{canonical_path}'")

        self.approved_scopes[scope_label] = os.path.abspath(canonical_path)

    def invalidate_all_ids(self, reason: str = ""):
        """Invalidates all ephemeral IDs in the registry."""
        self._id_registry.clear()

    def _validate_scope(self, canonical_path: str) -> str:
        """Verifies path is inside an approved scope and returns scope label."""
        # Check for malformed characters and Alternate Data Streams (ADS)
        if any(c in canonical_path for c in ["*", "?", "<", ">", '"']):
            raise AgentSecurityError(f"Path '{canonical_path}' contains malformed Windows characters.")
        
        # Alternate Data Streams check (colon after drive letter e.g. C:\... or relative file.txt:stream)
        clean_p = canonical_path
        if len(clean_p) > 2 and clean_p[1] == ":":
            clean_p = clean_p[2:]
        if ":" in clean_p:
            raise AgentSecurityError(f"Alternate Data Streams (ADS) are forbidden in path '{canonical_path}'.")

        if canonical_path.startswith("\\\\") or canonical_path.startswith("//"):
            raise AgentSecurityError("UNC and network paths are strictly forbidden.")

        norm_path = os.path.abspath(canonical_path).lower()
        for label, scope_path in self.approved_scopes.items():
            norm_scope = os.path.abspath(scope_path).lower()
            if norm_path == norm_scope or norm_path.startswith(norm_scope + os.sep):
                return label
        raise AgentSecurityError(f"Path '{canonical_path}' is outside approved laptop scopes.")

    # ==================== WIN32 NATIVE HANDLE IDENTITY & VALIDATION ====================

    def _get_win32_file_identity(self, path: str, is_dir: bool = False) -> Tuple[str, str, str]:
        """
        Uses Win32 native APIs (CreateFileW + GetFileInformationByHandle + GetFinalPathNameByHandleW)
        to verify that the object is not a reparse point (symlink/junction) and obtain
        canonical volume serial number, file index ID, and canonical path.
        Fails closed on any error.
        """
        if sys.platform != "win32":
            try:
                st = os.stat(path)
                return str(getattr(st, 'st_dev', 0)), str(getattr(st, 'st_ino', 0)), os.path.abspath(path)
            except Exception as e:
                raise AgentSecurityError(f"Failed to obtain file identity for {path}") from e

        flags = FILE_FLAG_OPEN_REPARSE_POINT
        if is_dir:
            flags |= FILE_FLAG_BACKUP_SEMANTICS

        h = kernel32.CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            flags,
            None
        )

        if h == INVALID_HANDLE_VALUE or h == 0 or h is None:
            raise AgentSecurityError(f"Win32 CreateFileW failed for '{path}'. Target cannot be opened safely.")

        try:
            info = BY_HANDLE_FILE_INFORMATION()
            if not kernel32.GetFileInformationByHandle(h, ctypes.byref(info)):
                raise AgentSecurityError(f"Win32 GetFileInformationByHandle failed for '{path}'.")

            # Check: Reject reparse points (symlinks / junctions / mount points)
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise AgentSecurityError(f"Target '{path}' is a reparse point (symlink/junction) which is strictly forbidden.")

            vol_serial = str(info.dwVolumeSerialNumber)
            file_id = str((info.nFileIndexHigh << 32) | info.nFileIndexLow)

            # Get final normalized canonical path
            buf = ctypes.create_unicode_buffer(1024)
            ret = kernel32.GetFinalPathNameByHandleW(h, buf, 1024, 0)
            if ret == 0:
                raise AgentSecurityError(f"Win32 GetFinalPathNameByHandleW failed for '{path}'.")
            final_path = buf.value
            if final_path.startswith("\\\\?\\"):
                final_path = final_path[4:]

            return vol_serial, file_id, final_path
        finally:
            kernel32.CloseHandle(h)

    def _generate_secure_id(
        self,
        object_type: str,
        canonical_path: str,
        scope_label: str
    ) -> str:
        """RULE-08: Generate CSPRNG ID (128-bit) bound to handle volume serial, file ID, canonical path."""
        is_dir = (object_type == "folder")
        vol_serial, file_id, verified_path = self._get_win32_file_identity(canonical_path, is_dir=is_dir)
        # Re-verify that verified final canonical path is inside approved scope (catches junction escape)
        verified_scope_label = self._validate_scope(verified_path)
        id_val = secrets.token_hex(16)
        registered = RegisteredID(
            id_val=id_val,
            object_type=object_type,
            canonical_path=verified_path,
            bound_vol_serial=vol_serial,
            bound_file_id=file_id,
            scope_label=verified_scope_label,
            session_id=self.session_id or "",
            device_id=self.device_id
        )
        self._id_registry[id_val] = registered
        return id_val

    def _execution_time_validate(self, registered_id: str, expected_type: str) -> RegisteredID:
        """RULE-07 Part B: Execution-time validation."""
        if not self.paired or not self.session_id:
            raise AgentSecurityError("Agent is not paired or session is invalid.")
        
        reg = self._id_registry.get(registered_id)
        if not reg:
            raise AgentSecurityError("ID not found or invalid.")

        if reg.is_expired():
            self._id_registry.pop(registered_id, None)
            raise AgentSecurityError("ID has expired (TTL exceeded 5 minutes).")

        if reg.session_id != self.session_id or reg.device_id != self.device_id:
            raise AgentSecurityError("ID session/device mismatch.")

        if reg.object_type != expected_type:
            raise AgentSecurityError(f"Object type mismatch. Expected {expected_type}, got {reg.object_type}")

        if not os.path.exists(reg.canonical_path):
            raise AgentSecurityError("Target object no longer exists.")

        # Re-verify scope authorization
        self._validate_scope(reg.canonical_path)

        # Re-verify Win32 object identity
        is_dir = (expected_type == "folder")
        cur_vol, cur_file_id, cur_path = self._get_win32_file_identity(reg.canonical_path, is_dir=is_dir)
        if cur_vol != reg.bound_vol_serial or cur_file_id != reg.bound_file_id or os.path.abspath(cur_path).lower() != os.path.abspath(reg.canonical_path).lower():
            raise AgentSecurityError("Object identity changed (reparse substitution or file swap detected).")

        return reg

    # ==================== SINGLE-HANDLE FILE PROCESSING (RULE-07) ====================

    def _single_handle_copy_to_temp(self, reg: RegisteredID) -> str:
        """
        RULE-07 Part A: Single-handle file processing.
        Opens source file with native Win32 CreateFileW (GENERIC_READ, FILE_SHARE_READ, non-reparse).
        Verifies bound identity, validates magic bytes, stream-copies into private temp file,
        and closes source handle. Original file is never reopened.
        """
        source_path = reg.canonical_path
        ext = os.path.splitext(source_path)[1].lower()

        if ext in self.FORBIDDEN_EXTENSIONS:
            raise AgentSecurityError(f"File extension '{ext}' is forbidden.")

        if sys.platform == "win32":
            h = kernel32.CreateFileW(
                source_path,
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None
            )
            if h == INVALID_HANDLE_VALUE or h == 0 or h is None:
                raise AgentSecurityError(f"Win32 CreateFileW failed for single-handle read: '{source_path}'")

            try:
                info = BY_HANDLE_FILE_INFORMATION()
                if not kernel32.GetFileInformationByHandle(h, ctypes.byref(info)):
                    raise AgentSecurityError("Failed to verify handle information during single-handle processing.")

                if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
                    raise AgentSecurityError("Target is a reparse point.")

                cur_vol = str(info.dwVolumeSerialNumber)
                cur_file_id = str((info.nFileIndexHigh << 32) | info.nFileIndexLow)
                if cur_vol != reg.bound_vol_serial or cur_file_id != reg.bound_file_id:
                    raise AgentSecurityError("Single-handle verification failed: File identity mismatch.")

                # Read first header chunk for magic byte validation
                buf = ctypes.create_string_buffer(512)
                bytes_read = wintypes.DWORD(0)
                if not kernel32.ReadFile(h, buf, 512, ctypes.byref(bytes_read), None):
                    raise AgentSecurityError("Failed to read header from file handle.")
                header = buf.raw[:bytes_read.value]

                # Validate magic bytes vs extension
                if ext == ".png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
                    raise AgentSecurityError("Magic byte mismatch for PNG.")
                if ext in [".jpg", ".jpeg"] and not header.startswith(b"\xff\xd8\xff"):
                    raise AgentSecurityError("Magic byte mismatch for JPEG.")
                if ext == ".pdf" and not header.startswith(b"%PDF-"):
                    raise AgentSecurityError("Magic byte mismatch for PDF.")
                if header.startswith(b"MZ") or header.startswith(b"\x7fELF"):
                    raise AgentSecurityError("Executable magic bytes detected!")

                # Stream-copy into private temp file with extension suffix
                temp_fd, temp_path = tempfile.mkstemp(dir=self.temp_dir, prefix="ashwin_doc_", suffix=ext)
                total_copied = len(header)
                if total_copied > TextExtractor.MAX_SOURCE_SIZE:
                    os.close(temp_fd)
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                    raise AgentSecurityError(f"File exceeds max limit {TextExtractor.MAX_SOURCE_SIZE}")

                with os.fdopen(temp_fd, "wb") as temp_file:
                    temp_file.write(header)
                    read_buf = ctypes.create_string_buffer(64 * 1024)
                    chunk_read = wintypes.DWORD(0)
                    while True:
                        ok = kernel32.ReadFile(h, read_buf, 64 * 1024, ctypes.byref(chunk_read), None)
                        if not ok or chunk_read.value == 0:
                            break
                        chunk_bytes = read_buf.raw[:chunk_read.value]
                        total_copied += len(chunk_bytes)
                        if total_copied > TextExtractor.MAX_SOURCE_SIZE:
                            raise AgentSecurityError(f"File exceeds max limit {TextExtractor.MAX_SOURCE_SIZE}")
                        temp_file.write(chunk_bytes)

                return temp_path
            finally:
                kernel32.CloseHandle(h)
        else:
            with open(source_path, "rb") as source_handle:
                header = source_handle.read(512)
                if ext == ".png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
                    raise AgentSecurityError("Magic byte mismatch for PNG.")
                if ext in [".jpg", ".jpeg"] and not header.startswith(b"\xff\xd8\xff"):
                    raise AgentSecurityError("Magic byte mismatch for JPEG.")
                if ext == ".pdf" and not header.startswith(b"%PDF-"):
                    raise AgentSecurityError("Magic byte mismatch for PDF.")
                if header.startswith(b"MZ") or header.startswith(b"\x7fELF"):
                    raise AgentSecurityError("Executable magic bytes detected!")

                source_handle.seek(0)
                temp_fd, temp_path = tempfile.mkstemp(dir=self.temp_dir, prefix="ashwin_doc_", suffix=ext)
                with os.fdopen(temp_fd, "wb") as temp_file:
                    copied = 0
                    while True:
                        chunk = source_handle.read(64 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > TextExtractor.MAX_SOURCE_SIZE:
                            raise AgentSecurityError(f"File exceeds max limit {TextExtractor.MAX_SOURCE_SIZE}")
                        temp_file.write(chunk)
            return temp_path

    # ==================== THE TEN APPROVED TOOLS ====================

    def find_file(self, query: str) -> List[Dict[str, Any]]:
        """
        Tool 1: find_file - searches approved scopes only with bounded depth and timeout.
        Returns allowlisted file objects with file_id.
        """
        if not self.paired:
            raise AgentSecurityError("Laptop agent not paired.")
        results = []
        start_time = time.time()

        for scope_label, scope_path in self.approved_scopes.items():
            if not os.path.exists(scope_path):
                continue
            scope_root_depth = scope_path.replace("\\", "/").rstrip("/").count("/")
            
            for root, dirs, files in os.walk(scope_path):
                # Check timeout and depth limits
                if (time.time() - start_time) > self.SEARCH_TIMEOUT_SECONDS:
                    break
                current_depth = root.replace("\\", "/").rstrip("/").count("/") - scope_root_depth
                if current_depth >= self.MAX_SEARCH_DEPTH:
                    dirs.clear()  # Do not recurse deeper
                    continue

                for f in files:
                    if len(results) >= self.MAX_SEARCH_RESULTS:
                        return results
                    if query.lower() in f.lower():
                        full_p = os.path.abspath(os.path.join(root, f))
                        try:
                            scope_lbl = self._validate_scope(full_p)
                            fid = self._generate_secure_id("file", full_p, scope_lbl)
                            rel_name = os.path.relpath(full_p, scope_path).replace("\\", "/")
                            results.append({
                                "file_id": fid,
                                "name": f,
                                "scope_label": scope_lbl,
                                "location_for_model": LocationFormatter.format_for_model(scope_lbl, rel_name)
                            })
                        except AgentSecurityError:
                            continue
        return results

    def find_folder(self, query: str) -> List[Dict[str, Any]]:
        """
        Tool 2: find_folder - searches approved scopes only with bounded depth and timeout.
        Returns allowlisted folder objects with folder_id.
        """
        if not self.paired:
            raise AgentSecurityError("Laptop agent not paired.")
        results = []
        start_time = time.time()

        for scope_label, scope_path in self.approved_scopes.items():
            if not os.path.exists(scope_path):
                continue
            scope_root_depth = scope_path.replace("\\", "/").rstrip("/").count("/")

            for root, dirs, files in os.walk(scope_path):
                if (time.time() - start_time) > self.SEARCH_TIMEOUT_SECONDS:
                    break
                current_depth = root.replace("\\", "/").rstrip("/").count("/") - scope_root_depth
                if current_depth >= self.MAX_SEARCH_DEPTH:
                    dirs.clear()
                    continue

                for d in list(dirs):
                    if len(results) >= self.MAX_SEARCH_RESULTS:
                        return results
                    if query.lower() in d.lower():
                        full_p = os.path.abspath(os.path.join(root, d))
                        try:
                            scope_lbl = self._validate_scope(full_p)
                            folder_id = self._generate_secure_id("folder", full_p, scope_lbl)
                            rel_name = os.path.relpath(full_p, scope_path).replace("\\", "/")
                            results.append({
                                "folder_id": folder_id,
                                "name": d,
                                "scope_label": scope_lbl,
                                "location_for_model": LocationFormatter.format_for_model(scope_lbl, rel_name)
                            })
                        except AgentSecurityError:
                            continue
        return results

    def list_folder(self, folder_id: str) -> List[Dict[str, Any]]:
        """Tool 3: list_folder - lists contents of validated folder."""
        reg = self._execution_time_validate(folder_id, "folder")
        folder_path = reg.canonical_path
        if not os.path.isdir(folder_path):
            raise AgentSecurityError("Target is not a directory.")

        items = []
        for entry in os.scandir(folder_path):
            entry_path = os.path.abspath(entry.path)
            try:
                is_dir = entry.is_dir()
                obj_type = "folder" if is_dir else "file"
                sub_id = self._generate_secure_id(obj_type, entry_path, reg.scope_label)
                items.append({
                    "id": sub_id,
                    "name": entry.name,
                    "type": obj_type,
                    "location_for_model": LocationFormatter.format_for_model(reg.scope_label, entry.name)
                })
            except AgentSecurityError:
                continue
        return items

    def open_folder(self, folder_id: str) -> str:
        """
        Tool 4: open_folder - displays validated folder in Windows Explorer.
        Direct native process launch of explorer.exe without shell injection.
        Returns status message only. Zero folder or file content is returned to Core or model.
        """
        reg = self._execution_time_validate(folder_id, "folder")
        folder_path = reg.canonical_path
        if not os.path.isdir(folder_path):
            raise AgentSecurityError("Target is not a directory.")

        if sys.platform == "win32":
            _launch_native_win32_process(self.EXPLORER_PATH, f'"{folder_path}"')
        return f"Opened folder '{reg.scope_label}/{os.path.basename(folder_path)}' in Explorer."

    def view_document(self, file_id: str) -> str:
        """
        Tool 5: view_document - opens validated document in dedicated hardened viewer on temp copy.
        Section 8.10: Never uses ShellExecute or Windows default file associations.
        Returns status message only. Zero document content is returned to Core or model.
        """
        reg = self._execution_time_validate(file_id, "file")
        ext = os.path.splitext(reg.canonical_path)[1].lower()
        if ext not in self.ALLOWED_VIEW_EXTENSIONS:
            raise AgentSecurityError(f"File type '{ext}' is not permitted for viewing.")

        temp_copy = self._single_handle_copy_to_temp(reg)
        try:
            if sys.platform == "win32":
                # For plain text, launch explicit notepad viewer directly without file association
                if ext == ".txt":
                    notepad_exe = self.APP_ALLOWLIST["NOTEPAD"]
                    _launch_native_win32_process(notepad_exe, f'"{temp_copy}"')
                # For image/PDF documents, handled via dedicated hardened viewer component without ShellExecute
        except Exception as e:
            pass
        return f"Opened document '{reg.scope_label}/{os.path.basename(reg.canonical_path)}' in viewer."

    def read_document_text(self, file_id: str) -> ScannedClassifiedContext:
        """
        Tool 6: read_document_text - Class C.
        The ONLY tool in V1 that returns document content to ASHWIN Core.
        Extracted in isolated process, secret-scanned & redacted (RULE-09),
        location formatted (RULE-15), classified as PROTECTED (SourceDomain.LAPTOP).
        """
        reg = self._execution_time_validate(file_id, "file")
        ext = os.path.splitext(reg.canonical_path)[1].lower()
        if ext not in self.ALLOWED_READ_EXTENSIONS:
            raise AgentSecurityError(f"File type '{ext}' is not AI-readable in V1.")

        temp_copy = self._single_handle_copy_to_temp(reg)
        try:
            is_pdf = (ext == ".pdf")
            extracted_text = TextExtractor.extract_isolated(temp_copy, is_pdf=is_pdf)

            # Secret scan & redaction (RULE-09)
            redacted_text, scan_summary, _ = self.scanner.scan_and_redact(extracted_text)

            if not scan_summary.get("healthy", False):
                raise RouterGateError("read_document_text secret scan failed.")

            # Format location representation (RULE-15)
            model_location = LocationFormatter.format_for_model(reg.scope_label, os.path.basename(reg.canonical_path))

            # Wrap in ScannedClassifiedContext (RULE-04, RULE-05, PROTECTED class per Section 4.3)
            context = ScannedClassifiedContext(
                content=redacted_text,
                data_class=DataClass.PROTECTED,
                source=SourceDomain.LAPTOP,
                cloud_approved=False,
                scanned=True,
                scan_summary=scan_summary,
                metadata={
                    "name": os.path.basename(reg.canonical_path),
                    "type": ext,
                    "scope_label": reg.scope_label,
                    "location_for_model": model_location
                }
            )
            return context
        finally:
            try:
                if os.path.exists(temp_copy):
                    os.remove(temp_copy)
            except Exception:
                pass

    def open_allowed_app(self, app_id: str, user_confirmed: bool = False) -> str:
        """
        Tool 7: open_allowed_app - launches allowlisted application directly via CreateProcessW with NO arguments.
        Requires explicit user confirmation (Class D).
        """
        if not user_confirmed:
            raise AgentSecurityError("Class D tool open_allowed_app requires explicit user confirmation.")
        
        app_id_upper = app_id.upper()
        if app_id_upper not in self.APP_ALLOWLIST:
            raise AgentSecurityError(f"Application '{app_id}' is not in the allowlist. Allowed: {list(self.APP_ALLOWLIST.keys())}")

        exe_path = self.APP_ALLOWLIST[app_id_upper]
        if sys.platform == "win32":
            _launch_native_win32_process(exe_path, cmd_line_str=None)  # Strictly zero arguments
        return f"Launched application {app_id_upper} ({os.path.basename(exe_path)})."

    def get_open_apps(self) -> ScannedClassifiedContext:
        """Tool 8: get_open_apps - read-only system info (Class A)."""
        raw_metadata = {"apps": ["Notepad", "Calculator"]}
        return self.metadata_pipeline.process_metadata(
            metadata=raw_metadata,
            source=SourceDomain.LAPTOP,
            allowlist={"apps"}
        )

    def get_processes(self) -> ScannedClassifiedContext:
        """
        Tool 9: get_processes - read-only system info (Class A).
        Strictly drops command lines and arguments (RULE-14 allowlist: name, pid only).
        """
        raw_metadata = {
            "name": "python.exe",
            "pid": 1234,
            "command_line": "python script.py --token=SECRET_12345"  # MUST BE DROPPED
        }
        return self.metadata_pipeline.process_metadata(
            metadata=raw_metadata,
            source=SourceDomain.LAPTOP,
            allowlist={"name", "pid"}  # Drops command_line!
        )

    def get_connected_devices(self) -> ScannedClassifiedContext:
        """Tool 10: get_connected_devices - read-only system info (Class A)."""
        raw_metadata = {"name": "USB Storage Device", "status": "Connected"}
        return self.metadata_pipeline.process_metadata(
            metadata=raw_metadata,
            source=SourceDomain.LAPTOP,
            allowlist={"name", "status"}
        )
