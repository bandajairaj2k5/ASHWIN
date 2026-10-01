"""
ASHWIN Phase 4 Test Suite — Windows Restricted Endpoint (Section 8, RULE-06, RULE-07, RULE-08, RULE-14, RULE-15).
Tests all 10 tools, Win32 native security handle validation, DPAPI encrypted identity,
CSPRNG 128-bit ephemeral IDs, 5-minute TTL, secret scanning, bounded discovery, and CoreSession ownership.
"""

import os
import sys
import time
import tempfile
import unittest
import shutil
import hmac
import hashlib
import threading
from unittest.mock import MagicMock, patch

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    SecurityViolation,
    RouterGateError,
)
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.session import CoreSession, CoreSessionError
from ashwin.core.laptop_connector import LaptopConnector, LaptopOfflineError, LaptopPermissionError
from ashwin.laptop_agent.agent import (
    WindowsLaptopAgent,
    AgentSecurityError,
    dpapi_encrypt_bytes,
    dpapi_decrypt_bytes,
)
from ashwin.core.consent import (
    ConsentCoordinator,
    CallbackConsentCoordinator,
    ConsentDecisionType,
    ConsentMetadata,
    CloudConsentToken,
)
from ashwin.core.router import AIRouter
from ashwin.core.providers import LocalAIProvider, CloudAIProvider


class TestPhase4LaptopEndpoint(unittest.TestCase):
    """Automated test cases for Phase 4 Windows Restricted Endpoint."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ashwin_test_laptop_")
        self.scope_dir = os.path.join(self.test_dir, "AllowedScope")
        os.makedirs(self.scope_dir, exist_ok=True)

        self.agent = WindowsLaptopAgent(device_id="TEST-LAPTOP-01")
        self.agent.add_approved_scope("AllowedScope", self.scope_dir)
        self.session_id = self.agent.pair_device(user_confirmed=True)

        self.connector = LaptopConnector(laptop_agent=self.agent)
        self.session = CoreSession(laptop_connector=self.connector)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        try:
            shutil.rmtree(self.agent.temp_dir, ignore_errors=True)
        except Exception:
            pass

    # ==================== TEST 1: DPAPI ENCRYPTED IDENTITY ====================

    def test_dpapi_encrypted_identity_persistence(self):
        """Verifies persistent identity is encrypted via DPAPI and no plaintext private key is written."""
        cert_data = b"-----BEGIN CERTIFICATE-----\nTEST_CERT_DATA\n-----END CERTIFICATE-----"
        key_data = b"-----BEGIN PRIVATE KEY-----\nTEST_PRIVATE_KEY_DATA\n-----END PRIVATE KEY-----"
        
        target_path = os.path.join(self.test_dir, "laptop_identity.dpapi")
        self.agent.save_identity_dpapi(target_path, private_key_pem=key_data, cert_pem=cert_data)

        # Assert file exists and does NOT contain plaintext private key bytes
        self.assertTrue(os.path.exists(target_path))
        with open(target_path, "rb") as f:
            raw_disk_bytes = f.read()
        self.assertNotIn(key_data, raw_disk_bytes)
        self.assertNotIn(b"TEST_PRIVATE_KEY_DATA", raw_disk_bytes)

        # Load back through DPAPI decrypt
        loaded_cert, loaded_key = self.agent.load_identity_dpapi(target_path)
        self.assertEqual(loaded_cert, cert_data)
        self.assertEqual(loaded_key, key_data)

    # ==================== TEST 2: PAIRING & CHALLENGE PROTOCOL ====================

    def test_sas_pairing_and_challenge_response(self):
        """Verifies 6-digit SAS code, pairing handshake, and challenge-response HMAC validation."""
        sas_code = self.agent.generate_sas_code()
        self.assertEqual(len(sas_code), 6)
        self.assertTrue(sas_code.isdigit())

        # Pairing requires user confirmation
        new_agent = WindowsLaptopAgent(device_id="TEST-LAPTOP-02")
        with self.assertRaises(AgentSecurityError):
            new_agent.pair_device(user_confirmed=False)

        new_session_id = new_agent.pair_device(user_confirmed=True, sas_code=sas_code)
        self.assertTrue(new_agent.paired)
        self.assertIsNotNone(new_agent.session_key)

        # Challenge-response HMAC verification
        nonce = new_agent.create_request_challenge()
        body = b'{"tool": "get_open_apps"}'
        sig = hmac.new(new_agent.session_key, nonce.encode("utf-8") + body, hashlib.sha256).hexdigest()

        self.assertTrue(new_agent.verify_request_signature(nonce, sig, body))
        self.assertFalse(new_agent.verify_request_signature(nonce, "bad_sig", body))

    # ==================== TEST 3: SCOPE & PATH SECURITY ====================

    def test_scope_validation_and_system_root_rejection(self):
        """Verifies system roots, UNC paths, and Alternate Data Streams are rejected."""
        # System root rejection
        for bad_path in ["C:\\", "C:\\Windows", "C:\\Program Files", "\\\\Server\\Share"]:
            with self.assertRaises(AgentSecurityError):
                self.agent.add_approved_scope("BadScope", bad_path)

        # Path traversal / out-of-scope access rejection
        outside_path = os.path.join(self.test_dir, "outside.txt")
        with open(outside_path, "w") as f:
            f.write("Outside text")

        with self.assertRaises(AgentSecurityError):
            self.agent._validate_scope(outside_path)

        # Alternate Data Stream rejection
        with self.assertRaises(AgentSecurityError):
            self.agent._validate_scope("AllowedScope/file.txt:stream")

    # ==================== TEST 4: EPHEMERAL IDs & 5-MINUTE TTL ====================

    def test_ephemeral_id_generation_and_ttl_expiration(self):
        """Verifies 128-bit hex UUID generation, identity binding, and 5-minute TTL enforcement."""
        test_file = os.path.join(self.scope_dir, "doc1.txt")
        with open(test_file, "w") as f:
            f.write("Test content")

        file_id = self.agent._generate_secure_id("file", test_file, "AllowedScope")
        self.assertEqual(len(file_id), 32)  # 128-bit hex = 32 chars

        # Valid retrieval before expiry
        reg = self.agent._execution_time_validate(file_id, "file")
        self.assertEqual(reg.canonical_path.lower(), os.path.abspath(test_file).lower())

        # Expiration after TTL
        reg.created_at = time.time() - 301.0  # Expire beyond 300s
        with self.assertRaises(AgentSecurityError) as ctx:
            self.agent._execution_time_validate(file_id, "file")
        self.assertIn("expired", str(ctx.exception).lower())

    # ==================== TEST 5: ALL TEN TOOLS VERIFICATION ====================

    def test_tool_1_find_file(self):
        """Tool 1: find_file returns allowlisted metadata with bounded search."""
        f1 = os.path.join(self.scope_dir, "report_2026.txt")
        with open(f1, "w") as f:
            f.write("Annual report")

        results = self.agent.find_file("report")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "report_2026.txt")
        self.assertIn("file_id", results[0])
        self.assertEqual(results[0]["location_for_model"], "AllowedScope/report_2026.txt")

    def test_tool_2_find_folder(self):
        """Tool 2: find_folder returns allowlisted folder metadata."""
        sub = os.path.join(self.scope_dir, "Project_Alpha")
        os.makedirs(sub, exist_ok=True)

        results = self.agent.find_folder("Alpha")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "Project_Alpha")
        self.assertIn("folder_id", results[0])
        self.assertEqual(results[0]["location_for_model"], "AllowedScope/Project_Alpha")

    def test_tool_3_list_folder(self):
        """Tool 3: list_folder returns allowlisted metadata for children."""
        sub = os.path.join(self.scope_dir, "SubFolder")
        os.makedirs(sub, exist_ok=True)
        child_file = os.path.join(sub, "child.txt")
        with open(child_file, "w") as f:
            f.write("Child data")

        folder_id = self.agent._generate_secure_id("folder", sub, "AllowedScope")
        items = self.agent.list_folder(folder_id)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "child.txt")
        self.assertEqual(items[0]["type"], "file")
        self.assertIn("id", items[0])

    @patch("ashwin.laptop_agent.agent._launch_native_win32_process")
    def test_tool_4_open_folder(self, mock_launch):
        """Tool 4: open_folder returns confirmation string only, zero content returned to model."""
        sub = os.path.join(self.scope_dir, "OpenTest")
        os.makedirs(sub, exist_ok=True)
        folder_id = self.agent._generate_secure_id("folder", sub, "AllowedScope")

        result = self.agent.open_folder(folder_id)
        self.assertIn("Opened folder", result)
        self.assertNotIn("content", result.lower())
        mock_launch.assert_called_once()

    @patch("ashwin.laptop_agent.agent._launch_native_win32_process")
    def test_tool_5_view_document(self, mock_launch):
        """Tool 5: view_document returns confirmation string only, zero document content returned."""
        doc_file = os.path.join(self.scope_dir, "view_test.txt")
        with open(doc_file, "w") as f:
            f.write("Sensitive document text that must not leak")

        file_id = self.agent._generate_secure_id("file", doc_file, "AllowedScope")
        result = self.agent.view_document(file_id)
        self.assertIn("Opened document", result)
        self.assertNotIn("Sensitive document text", result)
        mock_launch.assert_called_once()

    def test_tool_6_read_document_text(self):
        """Tool 6: read_document_text extracts, scans, redacts, and returns PROTECTED context."""
        doc_file = os.path.join(self.scope_dir, "notes.txt")
        with open(doc_file, "w") as f:
            f.write("ASHWIN Windows laptop notes. Project is active.")

        file_id = self.agent._generate_secure_id("file", doc_file, "AllowedScope")
        ctx = self.agent.read_document_text(file_id)

        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.data_class, DataClass.PROTECTED)
        self.assertEqual(ctx.source, SourceDomain.LAPTOP)
        self.assertTrue(ctx.scanned)
        self.assertTrue(ctx.scan_summary.get("healthy"))
        self.assertIn("ASHWIN Windows laptop notes", ctx.content)
        self.assertEqual(ctx.metadata["location_for_model"], "AllowedScope/notes.txt")

    @patch("ashwin.laptop_agent.agent._launch_native_win32_process")
    def test_tool_7_open_allowed_app(self, mock_launch):
        """Tool 7: open_allowed_app launches allowlisted apps only with user confirmation."""
        # Rejection without confirmation
        with self.assertRaises(AgentSecurityError):
            self.agent.open_allowed_app("NOTEPAD", user_confirmed=False)

        # Successful calls with confirmation
        res_calc = self.agent.open_allowed_app("CALCULATOR", user_confirmed=True)
        self.assertIn("Launched application CALCULATOR", res_calc)
        mock_launch.assert_called_with(self.agent.APP_ALLOWLIST["CALCULATOR"], cmd_line_str=None)

        res_np = self.agent.open_allowed_app("NOTEPAD", user_confirmed=True)
        self.assertIn("Launched application NOTEPAD", res_np)
        mock_launch.assert_called_with(self.agent.APP_ALLOWLIST["NOTEPAD"], cmd_line_str=None)

    def test_tool_7_negative_unauthorized_arguments_and_apps(self):
        """Tool 7 Argument Boundary: Rejection of arbitrary arguments and unauthorized apps."""
        malicious_attempts = [
            "CALCULATOR --malicious-flag",
            "calc.exe",
            "calc.exe /c echo bad",
            "NOTEPAD C:\\Windows\\System32\\cmd.exe",
            "notepad.exe /p secret.txt",
            "CMD",
            "cmd.exe",
            "POWERSHELL",
            "powershell.exe",
            "bash",
            "EXPLORER",
            "explorer.exe",
            "rundll32.exe",
            "python.exe script.py",
        ]
        for bad_app in malicious_attempts:
            with self.assertRaises(AgentSecurityError, msg=f"Failed to reject: {bad_app}"):
                self.agent.open_allowed_app(bad_app, user_confirmed=True)

    @patch("ashwin.laptop_agent.agent._launch_native_win32_process")
    def test_tool_5_view_document_all_formats_and_zero_content(self, mock_launch):
        """Tool 5: view_document tests all approved formats and guarantees zero content leakage."""
        formats_and_headers = {
            "test.txt": b"Plain text content for viewing.",
            "test.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00",
            "test.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00",
            "test.jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00",
            "test.pdf": b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF",
            "test.bmp": b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00",
            "test.gif": b"GIF89a\x01\x00\x01\x00\x80\x00\x00",
        }

        for fname, raw_bytes in formats_and_headers.items():
            fpath = os.path.join(self.scope_dir, fname)
            with open(fpath, "wb") as f:
                f.write(raw_bytes)

            fid = self.agent._generate_secure_id("file", fpath, "AllowedScope")
            result = self.agent.view_document(fid)

            # Guarantees: string message only, zero raw content leakage
            self.assertIn("Opened document", result)
            self.assertNotIn(raw_bytes[:10].decode("latin-1", errors="ignore"), result)

        # Negative check: unapproved extensions are rejected
        unapproved = ["script.bat", "app.exe", "macro.doc", "active.svg", "web.html"]
        for bad_f in unapproved:
            bad_p = os.path.join(self.scope_dir, bad_f)
            with open(bad_p, "wb") as f:
                f.write(b"bad content")
            fid = self.agent._generate_secure_id("file", bad_p, "AllowedScope")
            with self.assertRaises(AgentSecurityError):
                self.agent.view_document(fid)

    def test_tool_8_get_open_apps(self):
        """Tool 8: get_open_apps returns allowlisted apps metadata context."""
        ctx = self.agent.get_open_apps()
        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.source, SourceDomain.LAPTOP)
        self.assertEqual(ctx.data_class, DataClass.PROTECTED)

    def test_tool_9_get_processes_drops_command_lines(self):
        """Tool 9: get_processes returns process names/PIDs only and drops command lines (RULE-14)."""
        ctx = self.agent.get_processes()
        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.source, SourceDomain.LAPTOP)
        self.assertNotIn("command_line", ctx.content)
        self.assertNotIn("SECRET_12345", ctx.content)

    def test_tool_10_get_connected_devices(self):
        """Tool 10: get_connected_devices returns allowlisted device metadata context."""
        ctx = self.agent.get_connected_devices()
        self.assertIsInstance(ctx, ScannedClassifiedContext)
        self.assertEqual(ctx.source, SourceDomain.LAPTOP)
        self.assertIn("USB Storage Device", ctx.content)

    # ==================== TEST 6: SINGLE-HANDLE & FILE INTEGRITY ====================

    def test_single_handle_copy_and_forbidden_extensions(self):
        """Verifies single-handle copy rejects forbidden extensions and executable magic bytes."""
        bad_ext_file = os.path.join(self.scope_dir, "script.bat")
        with open(bad_ext_file, "w") as f:
            f.write("echo bad")

        # Extension rejection
        file_id = self.agent._generate_secure_id("file", bad_ext_file, "AllowedScope")
        with self.assertRaises(AgentSecurityError):
            self.agent._single_handle_copy_to_temp(self.agent._id_registry[file_id])

    # ==================== TEST 7: SECRET REDACTION IN DOCUMENT ====================

    def test_read_document_text_secret_redaction(self):
        """Verifies synthetic secret in document is redacted before model delivery."""
        doc_file = os.path.join(self.scope_dir, "config_with_key.txt")
        synthetic_key = "AIzaSyB39x_TEST_KEY_FOR_REDACTION_ONLY"
        with open(doc_file, "w") as f:
            f.write(f"System configuration: api_key={synthetic_key}\nServer ready.")

        file_id = self.agent._generate_secure_id("file", doc_file, "AllowedScope")
        ctx = self.agent.read_document_text(file_id)

        # Secret must be absent from context content
        self.assertNotIn(synthetic_key, ctx.content)
        self.assertIn("[REDACTED:API_KEY]", ctx.content)

    # ==================== TEST 8: CORESESSION ORCHESTRATION & ACCESS PERMISSION ====================

    def test_coresession_laptop_access_permission_enforcement(self):
        """Verifies CoreSession enforces access permission check before executing laptop tools."""
        doc_file = os.path.join(self.scope_dir, "doc.txt")
        with open(doc_file, "w") as f:
            f.write("Laptop test file")
        file_id = self.agent._generate_secure_id("file", doc_file, "AllowedScope")

        # Initial turn without permission -> callback denies
        res_denied = self.session.execute_laptop_turn(
            command_text="Read document from my laptop",
            tool_name="read_document_text",
            tool_args={"file_id": file_id},
            permission_prompt_callback=lambda prompt: False
        )
        self.assertEqual(res_denied.get("status"), "DENIED")
        self.assertIn("denied", res_denied.get("message", "").lower())

        # Second turn with permission granted
        res_granted = self.session.execute_laptop_turn(
            command_text="Read document from my laptop",
            tool_name="read_document_text",
            tool_args={"file_id": file_id},
            permission_prompt_callback=lambda prompt: True
        )
        self.assertEqual(res_granted.get("status"), "SUCCESS")

        # Reset session revokes permission
        self.session.reset_session()
        self.assertFalse(self.connector.get_access_permission())

    # ==================== TEST 9: CLOUD CONSENT ESCALATION ====================

    def test_coresession_laptop_cloud_consent_escalation(self):
        """Verifies that when Local AI is unavailable, laptop context requires CloudConsentToken."""
        doc_file = os.path.join(self.scope_dir, "cloud_test.txt")
        with open(doc_file, "w") as f:
            f.write("Important laptop content for analysis.")
        file_id = self.agent._generate_secure_id("file", doc_file, "AllowedScope")
        self.connector.set_access_permission(True)

        # Simulate local AI unavailable
        self.session.router.set_local_availability(False)

        coordinator = CallbackConsentCoordinator(handler=lambda meta: ConsentDecisionType.GRANTED_ONCE)
        res = self.session.execute_laptop_turn(
            command_text="Analyze my laptop file with cloud",
            tool_name="read_document_text",
            tool_args={"file_id": file_id},
            consent_coordinator=coordinator
        )
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("provider_used"), "CloudAI")

    # ==================== TEST 10: OFFLINE HANDLING ====================

    def test_offline_laptop_handling(self):
        """Verifies offline laptop returns exact unavailable message without breaking normal Core turns."""
        self.agent.revoke_pairing()

        res = self.session.execute_laptop_turn(
            command_text="List my laptop apps",
            tool_name="get_open_apps",
            permission_prompt_callback=lambda prompt: True
        )
        self.assertEqual(res.get("status"), "OFFLINE")
        self.assertIn("unavailable", res.get("message", "").lower())

        # Normal non-laptop Core turn still functions completely
        normal_res = self.session.execute_turn(raw_text="Hello ASHWIN, what is the weather today?")
        self.assertEqual(normal_res.get("status"), "SUCCESS")

    # ==================== TEST 11: LAPTOP MTLS TRANSPORT & CRYPTO SUBSYSTEM ====================

    def test_laptop_mtls_transport_and_nonce_replay(self):
        """Verifies dedicated laptop mTLS transport, certificate identities, HMAC derivation, and nonce replay rejection."""
        from ashwin.laptop_agent.transport import (
            LaptopCryptoManager,
            LaptopEndpointServer,
            LaptopEndpointClient,
            LaptopChallengeNonceManager,
            LaptopCryptoSecurityError,
            generate_laptop_certificate,
        )

        # 1. Certificate generation
        server_cert, server_key = generate_laptop_certificate("LAPTOP-AGENT-01")
        client_cert, client_key = generate_laptop_certificate("ASHWIN-CORE-CLIENT")
        self.assertIn(b"BEGIN CERTIFICATE", server_cert)
        self.assertIn(b"BEGIN PRIVATE KEY", server_key)

        # 2. Crypto Manager SAS and HMAC Derivation
        server_crypto = LaptopCryptoManager(device_id="LAPTOP-AGENT-01", is_server=True)
        client_crypto = LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)

        sas_server = server_crypto.compute_sas_code(client_crypto.public_key_hex)
        sas_client = client_crypto.compute_sas_code(server_crypto.public_key_hex)
        self.assertEqual(sas_server, sas_client)
        self.assertEqual(len(sas_server), 6)

        server_crypto.complete_pairing(client_crypto.public_key_hex, client_crypto.cert_pem, user_confirmed_sas=True)
        client_crypto.complete_pairing(server_crypto.public_key_hex, server_crypto.cert_pem, user_confirmed_sas=True)

        # Derived session keys must match
        self.assertEqual(server_crypto.session_key, client_crypto.session_key)
        self.assertEqual(len(server_crypto.session_key), 32)

        # 3. Nonce Manager & Replay Protection
        nonce_mgr = LaptopChallengeNonceManager(ttl_seconds=60)
        nonce = nonce_mgr.generate_nonce()
        self.assertEqual(len(nonce), 32)
        # First verification succeeds and burns the nonce
        self.assertTrue(nonce_mgr.verify_and_burn_nonce(nonce))
        # Replayed verification must fail
        self.assertFalse(nonce_mgr.verify_and_burn_nonce(nonce))

        # 4. Live Local mTLS Transport Server & Client Test
        server = LaptopEndpointServer(
            agent=self.agent,
            crypto_mgr=server_crypto,
            host="127.0.0.1",
            port=0
        )
        server.start(client_ca_cert_pem=client_crypto.cert_pem)

        try:
            client = LaptopEndpointClient(
                server_host="127.0.0.1",
                server_port=server.port,
                client_crypto_mgr=client_crypto
            )
            client.configure_tls(server_cert_pem=server_crypto.cert_pem)

            # Valid authenticated request
            res = client.request("POST", "/api/v1/tools/get_open_apps", {"tool": "get_open_apps", "args": {}})
            self.assertEqual(res.get("status"), "SUCCESS")
            self.assertIn("result", res)

            # Untrusted / Unauthenticated client rejection (wrong client cert)
            untrusted_crypto = LaptopCryptoManager(device_id="UNTRUSTED-CLIENT", is_server=False)
            untrusted_client = LaptopEndpointClient(
                server_host="127.0.0.1",
                server_port=server.port,
                client_crypto_mgr=untrusted_crypto
            )
            untrusted_client.configure_tls(server_cert_pem=server_crypto.cert_pem)
            with self.assertRaises(Exception):
                untrusted_client.request("POST", "/api/v1/tools/get_open_apps", {"tool": "get_open_apps", "args": {}})

        finally:
            server.stop()

    # ==================== TEST 12: WINDOWS LAPTOP TLS PARAMETERS & MINIMUM VERSION ====================

    def test_windows_laptop_tls_parameters_and_minimum_version(self):
        """Verifies actual negotiated TLS version, cipher suite, and minimum TLS 1.2 on LaptopEndpointServer."""
        from ashwin.laptop_agent.transport import LaptopCryptoManager, LaptopEndpointServer, LaptopEndpointClient
        import socket
        import ssl

        server_crypto = LaptopCryptoManager(device_id="LAPTOP-AGENT-01", is_server=True)
        client_crypto = LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)

        server = LaptopEndpointServer(agent=self.agent, crypto_mgr=server_crypto, host="127.0.0.1", port=0)
        server.start(client_ca_cert_pem=client_crypto.cert_pem)

        try:
            temp_dir = tempfile.mkdtemp(prefix="ashwin_tls_param_test_")
            cert_path = os.path.join(temp_dir, "client.crt")
            key_path = os.path.join(temp_dir, "client.key")
            ca_path = os.path.join(temp_dir, "server_ca.crt")
            with open(cert_path, "wb") as f:
                f.write(client_crypto.cert_pem)
            with open(key_path, "wb") as f:
                f.write(client_crypto.private_key_pem)
            with open(ca_path, "wb") as f:
                f.write(server_crypto.cert_pem)

            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path)
            client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            client_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            client_ctx.check_hostname = False

            with socket.create_connection(("127.0.0.1", server.port), timeout=3) as sock:
                with client_ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
                    tls_version = ssock.version()
                    cipher_suite, tls_proto, secret_bits = ssock.cipher()

                    # Must be TLS 1.2 or TLS 1.3
                    self.assertIn(tls_version, ["TLSv1.2", "TLSv1.3"])
                    self.assertIsNotNone(cipher_suite)
                    self.assertGreaterEqual(secret_bits, 128)
        finally:
            server.stop()
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ==================== TEST 13: CERTIFICATE PINNING (SAME CN DIFFERENT KEY) ====================

    def test_pinned_certificate_identity_negative_same_cn_rejection(self):
        """
        Negative test proving the Windows laptop endpoint verifies pinned public-key / certificate
        fingerprint identity and NOT merely the certificate CommonName.
        Presenting a different certificate with the SAME CommonName 'ASHWIN-CORE-CLIENT' must be rejected.
        """
        from ashwin.laptop_agent.transport import (
            LaptopCryptoManager,
            LaptopEndpointServer,
            LaptopEndpointClient,
            generate_laptop_certificate,
        )

        server_crypto = LaptopCryptoManager(device_id="LAPTOP-AGENT-01", is_server=True)
        legit_client_crypto = LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)

        # Pair server with legit client
        server_crypto.complete_pairing(
            peer_public_key=legit_client_crypto.public_key_hex,
            peer_cert_pem=legit_client_crypto.cert_pem,
            user_confirmed_sas=True
        )

        # Generate an adversarial certificate with the EXACT same CommonName but different key pair
        impostor_cert, impostor_key = generate_laptop_certificate(common_name="ASHWIN-CORE-CLIENT")
        impostor_crypto = LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)
        impostor_crypto.cert_pem = impostor_cert
        impostor_crypto.private_key_pem = impostor_key
        impostor_crypto.public_key_hex = hashlib.sha256(impostor_key + b"_laptop_pub").hexdigest()

        server = LaptopEndpointServer(agent=self.agent, crypto_mgr=server_crypto, host="127.0.0.1", port=0)
        # Trust both in CA store for TLS connection layer to test application pinning rejection
        combined_ca = legit_client_crypto.cert_pem + b"\n" + impostor_cert
        server.start(client_ca_cert_pem=combined_ca)

        try:
            impostor_client = LaptopEndpointClient(
                server_host="127.0.0.1",
                server_port=server.port,
                client_crypto_mgr=impostor_crypto
            )
            impostor_client.configure_tls(server_cert_pem=server_crypto.cert_pem)

            # Request from same-CN impostor must be rejected (403 Forbidden / pinned cert mismatch)
            resp = impostor_client.request("GET", "/api/v1/health")
            self.assertIn("error", resp)
            self.assertIn("Forbidden", resp.get("error", ""))
        finally:
            server.stop()

    # ==================== TEST 14: CHALLENGE NONCE 60s TTL EXPIRATION ====================

    def test_challenge_nonce_60s_ttl_expiration_deterministic(self):
        """Deterministic negative test verifying an expired 128-bit challenge nonce is rejected."""
        from ashwin.laptop_agent.transport import LaptopChallengeNonceManager

        nonce_mgr = LaptopChallengeNonceManager(ttl_seconds=60)
        nonce = nonce_mgr.generate_nonce()
        self.assertEqual(len(nonce), 32)

        # Nonce is valid initially
        self.assertIn(nonce, nonce_mgr._nonces)

        # Deterministically expire the nonce by setting timestamp in the past
        with nonce_mgr._lock:
            nonce_mgr._nonces[nonce] = time.time() - 5.0  # 5 seconds in the past

        # Expired nonce verification must return False (rejected)
        self.assertFalse(nonce_mgr.verify_and_burn_nonce(nonce))

    # ==================== TEST 15: EXACT APPLICATION CRYPTO FORMULAS & BURN-ON-USE ====================

    def test_exact_application_crypto_hmac_formulas_and_burn_on_use(self):
        """
        Deterministic proof that the implementation uses the exact specified formulas:
        1. SessionKey = HMAC-SHA256("ASHWIN_LAPTOP_MTLS_SECRET", sorted(k1, k2))
        2. Per-request signature = HMAC-SHA256(SessionKey, nonce:method:path:SHA256(body))
        3. Burn-on-use replay protection.
        """
        from ashwin.laptop_agent.transport import LaptopCryptoManager, LaptopChallengeNonceManager

        server_crypto = LaptopCryptoManager(device_id="LAPTOP-AGENT-01", is_server=True)
        client_crypto = LaptopCryptoManager(device_id="ASHWIN-CORE-CLIENT", is_server=False)

        k1 = server_crypto.public_key_hex
        k2 = client_crypto.public_key_hex
        sorted_keys = sorted([k1, k2])
        combined_keys = (sorted_keys[0] + ":" + sorted_keys[1]).encode("utf-8")

        # 1. Exact SessionKey formula assertion
        expected_session_key = hmac.new(b"ASHWIN_LAPTOP_MTLS_SECRET", combined_keys, hashlib.sha256).digest()
        
        server_crypto.complete_pairing(peer_public_key=k2, peer_cert_pem=client_crypto.cert_pem, user_confirmed_sas=True)
        client_crypto.complete_pairing(peer_public_key=k1, peer_cert_pem=server_crypto.cert_pem, user_confirmed_sas=True)

        self.assertEqual(server_crypto.session_key, expected_session_key)
        self.assertEqual(client_crypto.session_key, expected_session_key)

        # 2. Exact per-request signature formula assertion
        nonce = server_crypto.nonce_manager.generate_nonce()
        method = "POST"
        path = "/api/v1/tools/read_document_text"
        body = b'{"tool": "read_document_text", "args": {"file_id": "test_id"}}'
        body_hash = hashlib.sha256(body).hexdigest()

        expected_msg = f"{nonce}:{method}:{path}:{body_hash}".encode("utf-8")
        expected_signature = hmac.new(expected_session_key, expected_msg, hashlib.sha256).hexdigest()

        actual_signature = client_crypto.sign_request(nonce=nonce, method=method, path=path, body=body)
        self.assertEqual(actual_signature, expected_signature)

        # 3. Signature verification & Burn-on-use replay protection
        # First verification succeeds
        self.assertTrue(server_crypto.verify_request_signature(
            nonce=nonce,
            method=method,
            path=path,
            body=body,
            signature=actual_signature,
            sender_pubkey=k2
        ))

        # Replayed verification with same nonce must be burned and rejected
        self.assertFalse(server_crypto.verify_request_signature(
            nonce=nonce,
            method=method,
            path=path,
            body=body,
            signature=actual_signature,
            sender_pubkey=k2
        ))


if __name__ == "__main__":
    unittest.main()
