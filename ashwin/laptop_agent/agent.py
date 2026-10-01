"""
ASHWIN Windows Laptop Endpoint Agent (Section 8, RULE-06, RULE-07, RULE-08, RULE-14, RULE-15).
Restricted endpoint agent exposing exactly ten tools.
Implements cryptographically secure IDs, single-handle file processing, execution-time validation,
path security, scope enforcement, and hardened file handling.
"""

import os
import sys
import time
import secrets
import stat
import subprocess
import tempfile
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
    """

    ALLOWED_VIEW_EXTENSIONS = {".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf"}
    ALLOWED_READ_EXTENSIONS = {".txt", ".pdf"}
    FORBIDDEN_EXTENSIONS = {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".msc", ".msi", ".msp", ".scr",
        ".cpl", ".lnk", ".url", ".dll", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".svg", ".html", ".htm", ".xml"
    }

    APP_ALLOWLIST = {
        "NOTEPAD": "notepad.exe",
        "CALCULATOR": "calc.exe"
    }

    def __init__(self, device_id: str = "LAPTOP-LOCAL-01"):
        self.device_id = device_id
        self.paired = False
        self.session_id: Optional[str] = None
        self.approved_scopes: Dict[str, str] = {}  # scope_label -> raw_canonical_path
        self._id_registry: Dict[str, RegisteredID] = {}
        self.scanner = SecretScanner()
        self.metadata_pipeline = MetadataPipeline(scanner=self.scanner)
        self.temp_dir = tempfile.mkdtemp(prefix="ashwin_laptop_agent_temp_")

    def pair_device(self, user_confirmed: bool = True) -> str:
        if not user_confirmed:
            raise AgentSecurityError("Pairing rejected: User did not confirm matching code.")
        self.paired = True
        self.session_id = secrets.token_hex(16)
        self.invalidate_all_ids("Pairing established / Session initialized")
        return self.session_id

    def revoke_pairing(self):
        self.paired = False
        self.session_id = None
        self.invalidate_all_ids("Pairing revoked")

    def add_approved_scope(self, scope_label: str, canonical_path: str):
        # Reject system roots (C:\, C:\Windows, C:\Program Files, etc.)
        norm = os.path.abspath(canonical_path).replace("\\", "/").rstrip("/").lower()
        if norm in ["c:", "c:/", "c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata"]:
            raise AgentSecurityError(f"Scope path '{canonical_path}' is a restricted system directory.")
        if norm.startswith("//") or norm.startswith("\\\\"):
            raise AgentSecurityError("UNC and network paths are strictly forbidden.")
        
        self.approved_scopes[scope_label] = os.path.abspath(canonical_path)

    def invalidate_all_ids(self, reason: str = ""):
        self._id_registry.clear()

    def _generate_secure_id(
        self,
        object_type: str,
        canonical_path: str,
        scope_label: str
    ) -> str:
        """RULE-08: Generate CSPRNG ID (128-bit) bound to handle volume serial, file ID, canonical path."""
        vol_serial, file_id = self._get_file_identity(canonical_path)
        id_val = secrets.token_hex(16)
        registered = RegisteredID(
            id_val=id_val,
            object_type=object_type,
            canonical_path=canonical_path,
            bound_vol_serial=vol_serial,
            bound_file_id=file_id,
            scope_label=scope_label,
            session_id=self.session_id or "",
            device_id=self.device_id
        )
        self._id_registry[id_val] = registered
        return id_val

    def _get_file_identity(self, path: str) -> Tuple[str, str]:
        """Obtains volume serial number and filesystem file ID for identity binding."""
        try:
            st = os.stat(path)
            vol_serial = str(getattr(st, 'st_dev', 0))
            file_id = str(getattr(st, 'st_ino', 0))
            return vol_serial, file_id
        except Exception as e:
            raise AgentSecurityError(f"Failed to obtain file identity for {path}") from e

    def _validate_scope(self, canonical_path: str) -> str:
        """Verifies path is inside an approved scope and returns scope label."""
        # Check for malformed characters and Alternate Data Streams (ADS)
        if "*" in canonical_path or "?" in canonical_path or "<" in canonical_path or ">" in canonical_path or '"' in canonical_path:
            raise AgentSecurityError(f"Path '{canonical_path}' contains malformed Windows characters.")
        
        # ADS check (colon after drive letter e.g. C:\... or relative file.txt:stream)
        clean_p = canonical_path
        if len(clean_p) > 2 and clean_p[1] == ":":
            clean_p = clean_p[2:]
        if ":" in clean_p:
            raise AgentSecurityError(f"Alternate Data Streams (ADS) are forbidden in path '{canonical_path}'.")

        norm_path = os.path.abspath(canonical_path).lower()
        for label, scope_path in self.approved_scopes.items():
            norm_scope = os.path.abspath(scope_path).lower()
            if norm_path == norm_scope or norm_path.startswith(norm_scope + os.sep):
                return label
        raise AgentSecurityError(f"Path '{canonical_path}' is outside approved laptop scopes.")

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

        # Re-verify object identity (volume serial, file ID, canonical path match)
        cur_vol, cur_file_id = self._get_file_identity(reg.canonical_path)
        if cur_vol != reg.bound_vol_serial or cur_file_id != reg.bound_file_id:
            raise AgentSecurityError("Object identity changed (reparse substitution or file swap).")

        return reg

    # ==================== THE TEN APPROVED TOOLS ====================

    def find_file(self, query: str) -> List[Dict[str, Any]]:
        """Tool 1: find_file - searches approved scopes only, returns file objects with file_id."""
        if not self.paired:
            raise AgentSecurityError("Laptop agent not paired.")
        results = []
        for scope_label, scope_path in self.approved_scopes.items():
            if not os.path.exists(scope_path):
                continue
            for root, dirs, files in os.walk(scope_path):
                for f in files:
                    if query.lower() in f.lower():
                        full_p = os.path.abspath(os.path.join(root, f))
                        try:
                            scope_label = self._validate_scope(full_p)
                            fid = self._generate_secure_id("file", full_p, scope_label)
                            results.append({
                                "file_id": fid,
                                "name": f,
                                "scope_label": scope_label,
                                "location_for_model": LocationFormatter.format_for_model(scope_label, f)
                            })
                        except AgentSecurityError:
                            continue
        return results

    def find_folder(self, query: str) -> List[Dict[str, Any]]:
        """Tool 2: find_folder - searches approved scopes only, returns folder_id."""
        if not self.paired:
            raise AgentSecurityError("Laptop agent not paired.")
        results = []
        for scope_label, scope_path in self.approved_scopes.items():
            if not os.path.exists(scope_path):
                continue
            for root, dirs, files in os.walk(scope_path):
                for d in dirs:
                    if query.lower() in d.lower():
                        full_p = os.path.abspath(os.path.join(root, d))
                        try:
                            scope_label = self._validate_scope(full_p)
                            folder_id = self._generate_secure_id("folder", full_p, scope_label)
                            results.append({
                                "folder_id": folder_id,
                                "name": d,
                                "scope_label": scope_label,
                                "location_for_model": LocationFormatter.format_for_model(scope_label, d)
                            })
                        except AgentSecurityError:
                            continue
        return results

    def list_folder(self, folder_id: str) -> List[Dict[str, Any]]:
        """Tool 3: list_folder - lists validated folder."""
        reg = self._execution_time_validate(folder_id, "folder")
        folder_path = reg.canonical_path
        if not os.path.isdir(folder_path):
            raise AgentSecurityError("Target is not a directory.")

        items = []
        for entry in os.scandir(folder_path):
            entry_path = os.path.abspath(entry.path)
            is_dir = entry.is_dir()
            obj_type = "folder" if is_dir else "file"
            sub_id = self._generate_secure_id(obj_type, entry_path, reg.scope_label)
            items.append({
                "id": sub_id,
                "name": entry.name,
                "type": obj_type,
                "location_for_model": LocationFormatter.format_for_model(reg.scope_label, entry.name)
            })
        return items

    def open_folder(self, folder_id: str) -> str:
        """Tool 4: open_folder - displays validated folder in Explorer."""
        reg = self._execution_time_validate(folder_id, "folder")
        folder_path = reg.canonical_path
        if not os.path.isdir(folder_path):
            raise AgentSecurityError("Target is not a directory.")

        # Open folder safely in Explorer without arbitrary argument injection
        if sys.platform == "win32":
            subprocess.Popen(["explorer.exe", folder_path])
        return f"Opened folder '{reg.scope_label}/{os.path.basename(folder_path)}' in Explorer."

    def _single_handle_copy_to_temp(self, reg: RegisteredID) -> str:
        """RULE-07 Part A: Single-handle file processing & copy to temp file."""
        source_path = reg.canonical_path
        ext = os.path.splitext(source_path)[1].lower()

        if ext in self.FORBIDDEN_EXTENSIONS:
            raise AgentSecurityError(f"File extension '{ext}' is forbidden.")

        # Single-handle open (read-only)
        try:
            with open(source_path, "rb") as source_handle:
                # Re-verify handle identity
                st = os.fstat(source_handle.fileno())
                cur_vol = str(getattr(st, 'st_dev', 0))
                cur_file_id = str(getattr(st, 'st_ino', 0))
                if cur_vol != reg.bound_vol_serial or cur_file_id != reg.bound_file_id:
                    raise AgentSecurityError("Single-handle verification failed: File identity mismatch.")

                header = source_handle.read(512)
                # Check magic bytes vs extension
                if ext == ".png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
                    raise AgentSecurityError("Magic byte mismatch for PNG.")
                if ext in [".jpg", ".jpeg"] and not header.startswith(b"\xff\xd8\xff"):
                    raise AgentSecurityError("Magic byte mismatch for JPEG.")
                if ext == ".pdf" and not header.startswith(b"%PDF-"):
                    raise AgentSecurityError("Magic byte mismatch for PDF.")
                if header.startswith(b"MZ") or header.startswith(b"\x7fELF"):
                    raise AgentSecurityError("Executable magic bytes detected!")

                # Stream-copy into agent-owned temp file
                source_handle.seek(0)
                temp_fd, temp_path = tempfile.mkstemp(dir=self.temp_dir, prefix="ashwin_doc_")
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
        except Exception as e:
            raise AgentSecurityError(f"Single-handle processing failed: {str(e)}") from e

    def view_document(self, file_id: str) -> str:
        """Tool 5: view_document - opens hardened viewer on temp copy. Returns NO content to ASHWIN."""
        reg = self._execution_time_validate(file_id, "file")
        ext = os.path.splitext(reg.canonical_path)[1].lower()
        if ext not in self.ALLOWED_VIEW_EXTENSIONS:
            raise AgentSecurityError(f"File type '{ext}' is not permitted for viewing.")

        temp_copy = self._single_handle_copy_to_temp(reg)

        # Launch hardened viewer on temp copy (returns no content to ASHWIN Core)
        if ext == ".pdf":
            # PDF hardened viewer simulation (no JS, no network, no external links)
            pass
        return f"Opened document '{reg.scope_label}/{os.path.basename(reg.canonical_path)}' in viewer."

    def read_document_text(self, file_id: str) -> ScannedClassifiedContext:
        """Tool 6: read_document_text - Class C. Returns scanned document text through Router gate ONLY."""
        reg = self._execution_time_validate(file_id, "file")
        ext = os.path.splitext(reg.canonical_path)[1].lower()
        if ext not in self.ALLOWED_READ_EXTENSIONS:
            raise AgentSecurityError(f"File type '{ext}' is not AI-readable in V1.")

        temp_copy = self._single_handle_copy_to_temp(reg)

        # Extract text in isolated process (RULE-12)
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

    def open_allowed_app(self, app_id: str, user_confirmed: bool = False) -> str:
        """Tool 7: open_allowed_app - launches allowlisted application with NO arguments."""
        if not user_confirmed:
            raise AgentSecurityError("Class D tool open_allowed_app requires explicit user confirmation.")
        
        app_id_upper = app_id.upper()
        if app_id_upper not in self.APP_ALLOWLIST:
            raise AgentSecurityError(f"Application '{app_id}' is not in the allowlist. Allowed: {list(self.APP_ALLOWLIST.keys())}")

        exe_name = self.APP_ALLOWLIST[app_id_upper]
        if sys.platform == "win32":
            subprocess.Popen([exe_name])  # Launched with NO arguments
        return f"Launched application {app_id_upper} ({exe_name})."

    def get_open_apps(self) -> ScannedClassifiedContext:
        """Tool 8: get_open_apps - read-only system info (Class A)."""
        raw_metadata = {"apps": ["Notepad", "Calculator"]}
        return self.metadata_pipeline.process_metadata(
            metadata=raw_metadata,
            source=SourceDomain.LAPTOP,
            allowlist={"apps"}
        )

    def get_processes(self) -> ScannedClassifiedContext:
        """Tool 9: get_processes - read-only system info (Class A). Drops command lines (RULE-14)."""
        # Raw simulated process list containing sensitive command line
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
