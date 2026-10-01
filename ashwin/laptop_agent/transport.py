"""
ASHWIN Windows Laptop Endpoint mTLS Transport & Cryptographic Subsystem (Phase 4, Section 7.2, Section 8).
Implements dedicated TLS/mTLS server & client transport for the Windows Laptop Endpoint:
- X.509 EC P-256 self-signed certificates with CommonName 'LAPTOP-AGENT-01' and 'ASHWIN-CORE-CLIENT'.
- TLS 1.2 / TLS 1.3 mutual authentication (ssl.CERT_REQUIRED).
- Server certificate fingerprint pinning & client certificate validation.
- Short Authentication String (SAS) 6-digit OOB pairing code.
- Cryptographic 128-bit challenge nonce manager with 60-second TTL and burn-on-use replay protection.
- Session key derivation using HMAC-SHA256("ASHWIN_LAPTOP_MTLS_SECRET", sorted(k1, k2)).
- Per-request signature verification over nonce:method:path:SHA256(body).
- DPAPI-protected persistent storage for the laptop private key.
- Rejection of plaintext HTTP, untrusted certificates, and expired/replayed nonces.
"""

import os
import sys
import time
import json
import hmac
import ssl
import socket
import hashlib
import secrets
import threading
import datetime
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Any, Optional, Tuple, Set

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ashwin.laptop_agent.agent import (
    WindowsLaptopAgent,
    AgentSecurityError,
    dpapi_encrypt_bytes,
    dpapi_decrypt_bytes,
)


class LaptopCryptoSecurityError(Exception):
    """Raised for laptop cryptographic verification, certificate, or nonce replay failures."""
    pass


# ==================== CERTIFICATE GENERATION & IDENTITY ====================

def generate_laptop_certificate(common_name: str = "LAPTOP-AGENT-01") -> Tuple[bytes, bytes]:
    """Generates a self-signed X.509 certificate and EC P-256 private key for laptop endpoint."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    return cert_pem, key_pem


# ==================== CHALLENGE NONCE MANAGER ====================

class LaptopChallengeNonceManager:
    """
    Manages 128-bit single-use challenge nonces with 60-second TTL.
    Burn-on-use replay protection.
    """

    def __init__(self, ttl_seconds: int = 60):
        self.ttl_seconds = ttl_seconds
        self._nonces: Dict[str, float] = {}  # nonce_hex -> expiry_timestamp
        self._lock = threading.Lock()

    def generate_nonce(self) -> str:
        """Generates an unguessable 128-bit random nonce with 60s TTL."""
        nonce = secrets.token_hex(16)
        with self._lock:
            self._purge_expired()
            self._nonces[nonce] = time.time() + self.ttl_seconds
        return nonce

    def verify_and_burn_nonce(self, nonce: str) -> bool:
        """
        Verifies that a nonce exists and is unexpired, then immediately burns/deletes it.
        Returns True if valid, False if replayed, missing, or expired.
        """
        if not nonce or not isinstance(nonce, str):
            return False

        with self._lock:
            self._purge_expired()
            if nonce in self._nonces:
                del self._nonces[nonce]
                return True
            return False

    def _purge_expired(self):
        now = time.time()
        expired = [n for n, exp in self._nonces.items() if now > exp]
        for n in expired:
            del self._nonces[n]


# ==================== LAPTOP CRYPTO MANAGER ====================

class LaptopCryptoManager:
    """
    Manages asymmetric key material, SAS code generation, HMAC key derivation,
    and request signing for Windows Laptop Endpoint.
    """

    SAS_SALT = b"ASHWIN_LAPTOP_SAS_SALT"
    MTLS_SECRET_SALT = b"ASHWIN_LAPTOP_MTLS_SECRET"

    def __init__(self, device_id: str = "LAPTOP-AGENT-01", is_server: bool = True):
        self.device_id = device_id
        self.is_server = is_server
        self.cert_pem, self.private_key_pem = generate_laptop_certificate(device_id)
        self.public_key_hex = hashlib.sha256(self.private_key_pem + b"_laptop_pub").hexdigest()
        self.pinned_peer_pubkey: Optional[str] = None
        self.pinned_peer_cert_fp: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self.paired = False
        self.nonce_manager = LaptopChallengeNonceManager(ttl_seconds=60)

    def save_identity_dpapi(self, filepath: str):
        """Persists private key and certificate using DPAPI."""
        payload = b"---ASHWIN_LAPTOP_IDENTITY_V1---\n" + self.cert_pem + b"\n---KEY_DELIMITER---\n" + self.private_key_pem
        enc = dpapi_encrypt_bytes(payload, description="ASHWIN_LAPTOP_KEY")
        with open(filepath, "wb") as f:
            f.write(enc)

    def load_identity_dpapi(self, filepath: str):
        """Loads and decrypts identity from DPAPI-protected store."""
        if not os.path.exists(filepath):
            raise LaptopCryptoSecurityError(f"DPAPI file not found: {filepath}")
        with open(filepath, "rb") as f:
            enc = f.read()
        dec = dpapi_decrypt_bytes(enc)
        if b"---ASHWIN_LAPTOP_IDENTITY_V1---\n" not in dec:
            raise LaptopCryptoSecurityError("Invalid DPAPI payload header.")
        parts = dec.split(b"\n---KEY_DELIMITER---\n")
        self.cert_pem = parts[0].replace(b"---ASHWIN_LAPTOP_IDENTITY_V1---\n", b"")
        self.private_key_pem = parts[1]
        self.public_key_hex = hashlib.sha256(self.private_key_pem + b"_laptop_pub").hexdigest()

    def compute_sas_code(self, peer_public_key: str) -> str:
        """
        Computes 6-digit Short Authentication String (SAS) for visual OOB pairing.
        SAS = Truncate6Digits(HMAC_SHA256(min(k1,k2) || max(k1,k2)))
        """
        keys = sorted([self.public_key_hex, peer_public_key])
        combined = (keys[0] + ":" + keys[1]).encode("utf-8")
        h = hmac.new(self.SAS_SALT, combined, hashlib.sha256).hexdigest()
        num = int(h[:8], 16) % 1_000_000
        return f"{num:06d}"

    def complete_pairing(self, peer_public_key: str, peer_cert_pem: bytes, user_confirmed_sas: bool):
        """Completes pairing and derives symmetric authenticated session key."""
        if not user_confirmed_sas:
            raise LaptopCryptoSecurityError("Pairing Aborted: User did not confirm matching SAS code.")
        
        self.pinned_peer_pubkey = peer_public_key
        # Pin peer certificate fingerprint
        der = ssl.PEM_cert_to_DER_cert(peer_cert_pem.decode("latin-1", errors="ignore") if isinstance(peer_cert_pem, bytes) else peer_cert_pem)
        self.pinned_peer_cert_fp = hashlib.sha256(der).hexdigest()

        keys = sorted([self.public_key_hex, peer_public_key])
        combined = (keys[0] + ":" + keys[1]).encode("utf-8")
        self.session_key = hmac.new(self.MTLS_SECRET_SALT, combined, hashlib.sha256).digest()
        self.paired = True

    def revoke_pairing(self):
        """Revokes pairing immediately and purges session keys."""
        self.pinned_peer_pubkey = None
        self.pinned_peer_cert_fp = None
        self.session_key = None
        self.paired = False

    def sign_request(self, nonce: str, method: str, path: str, body: bytes) -> str:
        """Computes HMAC signature over nonce:method:path:SHA256(body)."""
        if not self.paired or not self.session_key:
            raise LaptopCryptoSecurityError("Cannot sign request: Laptop endpoint is not paired.")
        body_hash = hashlib.sha256(body).hexdigest()
        message = f"{nonce}:{method}:{path}:{body_hash}".encode("utf-8")
        return hmac.new(self.session_key, message, hashlib.sha256).hexdigest()

    def verify_request_signature(
        self,
        nonce: str,
        method: str,
        path: str,
        body: bytes,
        signature: str,
        sender_pubkey: str
    ) -> bool:
        """Verifies per-request signature and single-use challenge nonce."""
        if not self.paired or not self.session_key:
            return False
        if sender_pubkey != self.pinned_peer_pubkey:
            return False
        if not self.nonce_manager.verify_and_burn_nonce(nonce):
            return False  # Nonce missing, expired, or replayed

        body_hash = hashlib.sha256(body).hexdigest()
        message = f"{nonce}:{method}:{path}:{body_hash}".encode("utf-8")
        expected_sig = hmac.new(self.session_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected_sig)


# ==================== LIVE HTTPS / mTLS SERVER ====================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class LaptopHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler enforcing mTLS authentication, challenge-nonce verification,
    and dispatching to the 10 approved WindowsLaptopAgent tools.
    """

    def _verify_pinned_peer_cert(self) -> bool:
        if not self.server.crypto_mgr.paired or not self.server.crypto_mgr.pinned_peer_cert_fp:
            return True
        try:
            if hasattr(self.connection, "getpeercert"):
                peer_der = self.connection.getpeercert(binary_form=True)
                if peer_der:
                    fp = hashlib.sha256(peer_der).hexdigest()
                    return fp == self.server.crypto_mgr.pinned_peer_cert_fp
        except Exception:
            return False
        return True

    def do_GET(self):
        if not self._verify_pinned_peer_cert():
            self._send_json(403, {"error": "Forbidden: Peer certificate does not match pinned certificate identity."})
            return

        if self.path == "/api/v1/challenge":
            # Issue unguessable 128-bit challenge nonce (60s TTL)
            nonce = self.server.crypto_mgr.nonce_manager.generate_nonce()
            self._send_json(200, {"nonce": nonce, "ttl_seconds": 60})
            return

        if self.path == "/api/v1/health":
            self._send_json(200, {
                "status": "HEALTHY",
                "device_id": self.server.crypto_mgr.device_id,
                "paired": self.server.crypto_mgr.paired,
            })
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._verify_pinned_peer_cert():
            self._send_json(403, {"error": "Forbidden: Peer certificate does not match pinned certificate identity."})
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if self.path == "/api/v1/pair":
            try:
                payload = json.loads(body.decode("utf-8"))
                peer_pubkey = payload["peer_pubkey"]
                user_confirmed = payload.get("user_confirmed", False)
                peer_cert_pem = payload.get("peer_cert_pem", "").encode("utf-8")
                
                sas = self.server.crypto_mgr.compute_sas_code(peer_pubkey)
                if user_confirmed:
                    self.server.crypto_mgr.complete_pairing(peer_pubkey, peer_cert_pem, user_confirmed_sas=True)
                    self.server.agent.pair_device(user_confirmed=True)
                    self._send_json(200, {
                        "status": "PAIRED",
                        "sas_code": sas,
                        "session_id": self.server.agent.session_id,
                        "public_key": self.server.crypto_mgr.public_key_hex
                    })
                else:
                    self._send_json(200, {"status": "SAS_PENDING", "sas_code": sas})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # Authenticated Tool Invocation
        nonce = self.headers.get("X-Laptop-Nonce", "")
        signature = self.headers.get("X-Laptop-Signature", "")
        sender_pubkey = self.headers.get("X-Laptop-Sender-Pubkey", "")

        # Verify HMAC signature and burn nonce
        if not self.server.crypto_mgr.verify_request_signature(
            nonce=nonce,
            method="POST",
            path=self.path,
            body=body,
            signature=signature,
            sender_pubkey=sender_pubkey
        ):
            self._send_json(401, {"error": "Unauthorized: Invalid, replayed, or expired request signature."})
            return

        try:
            req_data = json.loads(body.decode("utf-8")) if body else {}
            tool_name = req_data.get("tool", "")
            tool_args = req_data.get("args", {})

            # Dispatch strictly to the 10 approved tools
            result = self._dispatch_tool(tool_name, tool_args)
            self._send_json(200, {"status": "SUCCESS", "result": result})
        except AgentSecurityError as e:
            self._send_json(403, {"status": "FORBIDDEN", "error": str(e)})
        except Exception as e:
            self._send_json(500, {"status": "ERROR", "error": str(e)})

    def _dispatch_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        agent = self.server.agent
        if tool_name == "find_file":
            return agent.find_file(args.get("query", ""))
        elif tool_name == "find_folder":
            return agent.find_folder(args.get("query", ""))
        elif tool_name == "list_folder":
            return agent.list_folder(args.get("folder_id", ""))
        elif tool_name == "open_folder":
            return agent.open_folder(args.get("folder_id", ""))
        elif tool_name == "view_document":
            return agent.view_document(args.get("file_id", ""))
        elif tool_name == "read_document_text":
            ctx = agent.read_document_text(args.get("file_id", ""))
            return {
                "content": ctx.content,
                "data_class": ctx.data_class.value,
                "source": ctx.source.value,
                "metadata": ctx.metadata,
                "scanned": ctx.scanned,
                "scan_summary": ctx.scan_summary,
            }
        elif tool_name == "open_allowed_app":
            return agent.open_allowed_app(args.get("app_id", ""), user_confirmed=args.get("user_confirmed", False))
        elif tool_name == "get_open_apps":
            ctx = agent.get_open_apps()
            return {"content": ctx.content, "data_class": ctx.data_class.value, "source": ctx.source.value}
        elif tool_name == "get_processes":
            ctx = agent.get_processes()
            return {"content": ctx.content, "data_class": ctx.data_class.value, "source": ctx.source.value}
        elif tool_name == "get_connected_devices":
            ctx = agent.get_connected_devices()
            return {"content": ctx.content, "data_class": ctx.data_class.value, "source": ctx.source.value}
        else:
            raise AgentSecurityError(f"Unsupported tool: {tool_name}")

    def _send_json(self, code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress default noisy console logs


class LaptopEndpointServer:
    """
    mTLS Server for Windows Laptop Agent.
    Enforces TLS 1.2/1.3, client certificate requirement, and peer identity validation.
    """

    def __init__(
        self,
        agent: Optional[WindowsLaptopAgent] = None,
        crypto_mgr: Optional[LaptopCryptoManager] = None,
        host: str = "127.0.0.1",
        port: int = 0
    ):
        self.host = host
        self.port = port
        self.agent = agent or WindowsLaptopAgent(device_id="LAPTOP-AGENT-01")
        self.crypto_mgr = crypto_mgr or LaptopCryptoManager(device_id="LAPTOP-AGENT-01")
        self.httpd: Optional[ThreadedHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self, client_ca_cert_pem: Optional[bytes] = None):
        """Configures mTLS socket context and starts HTTPS server."""
        self.httpd = ThreadedHTTPServer((self.host, self.port), LaptopHTTPRequestHandler)
        self.httpd.agent = self.agent
        self.httpd.crypto_mgr = self.crypto_mgr
        self.port = self.httpd.server_port

        # Write server cert & key to temporary files for SSLContext loading
        temp_dir = self.agent.temp_dir
        server_cert_path = os.path.join(temp_dir, "laptop_server.crt")
        server_key_path = os.path.join(temp_dir, "laptop_server.key")
        with open(server_cert_path, "wb") as f:
            f.write(self.crypto_mgr.cert_pem)
        with open(server_key_path, "wb") as f:
            f.write(self.crypto_mgr.private_key_pem)

        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)

        if client_ca_cert_pem:
            ca_path = os.path.join(temp_dir, "client_ca.crt")
            with open(ca_path, "wb") as f:
                f.write(client_ca_cert_pem)
            ssl_ctx.load_verify_locations(cafile=ca_path)
        else:
            # Self-signed acceptance for test CA
            ssl_ctx.load_verify_locations(cafile=server_cert_path)

        self.httpd.socket = ssl_ctx.wrap_socket(self.httpd.socket, server_side=True)

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass


# ==================== LIVE mTLS CLIENT ====================

class LaptopEndpointClient:
    """
    mTLS Client for CoreSession to communicate with Windows Laptop Endpoint.
    Enforces TLS 1.2/1.3, client certificate presentation, server pinning, and HMAC signing.
    """

    def __init__(
        self,
        server_host: str,
        server_port: int,
        client_crypto_mgr: Optional[LaptopCryptoManager] = None
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto_mgr = client_crypto_mgr or LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)
        self.ssl_ctx: Optional[ssl.SSLContext] = None

    def configure_tls(self, server_cert_pem: bytes):
        """Configures client TLS context with certificate pinning."""
        temp_dir = tempfile.mkdtemp(prefix="ashwin_core_client_tls_")
        cert_path = os.path.join(temp_dir, "client.crt")
        key_path = os.path.join(temp_dir, "client.key")
        ca_path = os.path.join(temp_dir, "server_pinned_ca.crt")

        with open(cert_path, "wb") as f:
            f.write(self.crypto_mgr.cert_pem)
        with open(key_path, "wb") as f:
            f.write(self.crypto_mgr.private_key_pem)
        with open(ca_path, "wb") as f:
            f.write(server_cert_pem)

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ctx.check_hostname = False
        self.ssl_ctx = ctx

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends an authenticated mTLS request."""
        if not self.ssl_ctx:
            raise LaptopCryptoSecurityError("Client TLS context not configured.")

        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else b""

        headers = {
            "Host": f"{self.server_host}:{self.server_port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
        }

        # Sign request if paired
        if self.crypto_mgr.paired and path.startswith("/api/v1/tools"):
            # Get challenge nonce from server
            nonce = self._get_challenge_nonce()
            signature = self.crypto_mgr.sign_request(nonce, method, path, body_bytes)
            headers["X-Laptop-Nonce"] = nonce
            headers["X-Laptop-Signature"] = signature
            headers["X-Laptop-Sender-Pubkey"] = self.crypto_mgr.public_key_hex

        import http.client
        conn = http.client.HTTPSConnection(self.server_host, self.server_port, context=self.ssl_ctx, timeout=5)
        try:
            conn.request(method, path, body=body_bytes if body_bytes else None, headers=headers)
            res = conn.getresponse()
            raw_body = res.read()
            if not raw_body:
                return {"status_code": res.status}
            return json.loads(raw_body.decode("utf-8"))
        finally:
            conn.close()

    def _get_challenge_nonce(self) -> str:
        """Fetches a 128-bit challenge nonce from server."""
        import http.client
        conn = http.client.HTTPSConnection(self.server_host, self.server_port, context=self.ssl_ctx, timeout=5)
        try:
            conn.request("GET", "/api/v1/challenge")
            res = conn.getresponse()
            raw_body = res.read()
            data = json.loads(raw_body.decode("utf-8"))
            return data["nonce"]
        finally:
            conn.close()
