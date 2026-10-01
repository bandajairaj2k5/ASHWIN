"""
ASHWIN Moto G3 Restricted Storage Server (Section 10, Section 14, Section 15).
Implements mTLS server dispatch handling 4 storage operations + challenge endpoint.
Strictly jailed to ASHWIN_STORAGE with 5 MB response cap and fail-closed security.
"""

import os
import json
import time
from typing import Dict, Any, Optional, Tuple

try:
    from ashwin.moto_endpoint.jail import StorageJail, JailSecurityError
    from ashwin.moto_endpoint.crypto import DeviceIdentity, ChallengeNonceManager, CryptoSecurityError
except ImportError:
    from jail import StorageJail, JailSecurityError
    from crypto import DeviceIdentity, ChallengeNonceManager, CryptoSecurityError


class MotoStorageServer:
    """
    Restricted Storage Server running on Moto G3.
    """

    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB hard limit (Section 15)

    def __init__(self, root_dir: str, device_id: str = "MOTO-G3-01"):
        self.jail = StorageJail(root_dir)
        self.identity = DeviceIdentity(device_id, is_server=True)
        self.nonce_manager = ChallengeNonceManager(ttl_seconds=60)
        self.running = True

    # =========================================================================
    # Request Dispatcher & Security Filter
    # =========================================================================

    def handle_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes
    ) -> Tuple[int, Dict[str, str], bytes]:
        """
        Main request dispatch entrypoint enforcing authentication, challenge burn,
        and path validation before invoking storage capabilities.
        """
        if not self.running:
            return 503, {"Content-Type": "application/json"}, b'{"error": "Server stopped"}'

        # Route 1: Challenge generation (unauthenticated pre-flight)
        if path == "/storage/v1/challenge" and method == "POST":
            nonce = self.nonce_manager.generate_nonce()
            resp_body = json.dumps({"nonce": nonce, "ttl": 60}).encode("utf-8")
            return 200, {"Content-Type": "application/json"}, resp_body

        # Route 2: Pairing Initiation / SAS exchange
        if path == "/storage/v1/pair" and method == "POST":
            try:
                data = json.loads(body.decode("utf-8"))
                client_pubkey = data.get("client_pubkey")
                user_sas_confirmed = data.get("user_sas_confirmed", False)
                if not client_pubkey:
                    return 400, {"Content-Type": "application/json"}, b'{"error": "Missing client public key"}'

                sas_code = self.identity.compute_sas_code(client_pubkey)
                if user_sas_confirmed:
                    self.identity.complete_pairing(client_pubkey, user_confirmed_sas=True)
                    return 200, {"Content-Type": "application/json"}, json.dumps({"status": "PAIRED", "sas": sas_code, "server_pubkey": self.identity.public_key}).encode("utf-8")
                else:
                    return 200, {"Content-Type": "application/json"}, json.dumps({"status": "PENDING_CONFIRMATION", "sas": sas_code, "server_pubkey": self.identity.public_key}).encode("utf-8")
            except Exception as e:
                return 400, {"Content-Type": "application/json"}, json.dumps({"error": str(e)}).encode("utf-8")

        # All other endpoints require active pairing, valid nonce, and signature
        if not self.identity.paired:
            return 401, {"Content-Type": "application/json"}, b'{"error": "Device is not paired"}'

        # Case-insensitive header extraction
        norm_headers = {k.lower(): v for k, v in headers.items()}
        nonce = norm_headers.get("x-moto-nonce", "")
        signature = norm_headers.get("x-moto-signature", "")
        sender_pubkey = norm_headers.get("x-client-pubkey", "")

        # Verify and burn challenge nonce (replay defense)
        if not self.nonce_manager.verify_and_burn_nonce(nonce):
            return 401, {"Content-Type": "application/json"}, b'{"error": "Invalid or expired challenge nonce"}'

        # Verify signature
        if not self.identity.verify_signature(nonce, method, path, body, signature, sender_pubkey):
            return 401, {"Content-Type": "application/json"}, b'{"error": "Signature verification failed"}'

        # Dispatch allowed operations
        try:
            if path == "/storage/v1/list" and method == "POST":
                return self._op_list(body)
            elif path == "/storage/v1/search" and method == "POST":
                return self._op_search(body)
            elif path == "/storage/v1/read" and method == "POST":
                return self._op_read(body)
            elif path == "/storage/v1/download" and method == "POST":
                return self._op_read(body)  # Same bounded read pipeline
            else:
                return 404, {"Content-Type": "application/json"}, b'{"error": "Endpoint not found"}'
        except JailSecurityError as jse:
            return 403, {"Content-Type": "application/json"}, json.dumps({"error": str(jse)}).encode("utf-8")
        except FileNotFoundError as fnf:
            return 404, {"Content-Type": "application/json"}, json.dumps({"error": str(fnf)}).encode("utf-8")
        except Exception as e:
            return 500, {"Content-Type": "application/json"}, json.dumps({"error": "Internal server error"}).encode("utf-8")

    # =========================================================================
    # Storage Capabilities (Section 10)
    # =========================================================================

    def _op_list(self, body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """Lists metadata of files inside approved subfolder."""
        data = json.loads(body.decode("utf-8")) if body else {}
        subfolder = data.get("subfolder", "")
        target_dir = self.jail.validate_and_resolve(subfolder, is_directory=True)

        entries = []
        for entry in os.scandir(target_dir):
            if entry.name.startswith("."):
                continue
            stat = entry.stat()
            entries.append({
                "name": entry.name,
                "size": str(stat.st_size),
                "date": time.strftime("%Y-%m-%d", time.gmtime(stat.st_mtime)),
                "type": "directory" if entry.is_dir() else "file"
            })

        return 200, {"Content-Type": "application/json"}, json.dumps({"items": entries}).encode("utf-8")

    def _op_search(self, body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """Searches files inside ASHWIN_STORAGE."""
        data = json.loads(body.decode("utf-8")) if body else {}
        query = data.get("query", "").lower()
        category = data.get("category", "")

        target_dir = self.jail.validate_and_resolve(category, is_directory=True) if category else self.jail.canonical_root

        matches = []
        for root, dirs, files in os.walk(target_dir):
            # Avoid traversing symlinks or hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and not os.path.islink(os.path.join(root, d))]
            for file in files:
                if file.startswith("."):
                    continue
                if query in file.lower():
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, self.jail.canonical_root).replace("\\", "/")
                    stat = os.stat(full_p)
                    matches.append({
                        "name": file,
                        "path": rel_p,
                        "size": str(stat.st_size),
                        "date": time.strftime("%Y-%m-%d", time.gmtime(stat.st_mtime)),
                        "type": "file"
                    })

        return 200, {"Content-Type": "application/json"}, json.dumps({"results": matches}).encode("utf-8")

    def _op_read(self, body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """Reads file bytes with strict 5 MB cap."""
        data = json.loads(body.decode("utf-8")) if body else {}
        rel_path = data.get("file_path", "")
        canonical_file = self.jail.validate_and_resolve(rel_path, is_directory=False)

        file_size = os.path.getsize(canonical_file)
        if file_size > self.MAX_FILE_SIZE:
            return 413, {"Content-Type": "application/json"}, b'{"error": "File size exceeds 5 MB security limit"}'

        with open(canonical_file, "rb") as f:
            file_bytes = f.read(self.MAX_FILE_SIZE + 1)

        if len(file_bytes) > self.MAX_FILE_SIZE:
            return 413, {"Content-Type": "application/json"}, b'{"error": "File size exceeds 5 MB security limit"}'

        return 200, {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(file_bytes))
        }, file_bytes
