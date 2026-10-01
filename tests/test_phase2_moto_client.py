"""
Unit tests for Phase 2: Android MotoStorageClient Protocol, Transport & Security Pipeline.
"""

import unittest
import json
import os
import shutil
import tempfile
import hashlib
import hmac

from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.credentials import CredentialStore
from ashwin.core.endpoint_config import EndpointConfig
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.extractor import TextExtractor, ExtractorError
from ashwin.core.location_formatter import LocationFormatter
from ashwin.moto_endpoint.crypto import DeviceIdentity, ChallengeNonceManager
from ashwin.moto_endpoint.jail import StorageJail
from ashwin.moto_endpoint.server import MotoStorageServer
from ashwin.moto_endpoint.moto_connector import MotoConnector, MotoSecurityError, MotoFeasibilityError


class TestPhase2MotoClientProtocol(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server = MotoStorageServer(root_dir=self.temp_dir)
        self.client = MotoConnector(device_id="CORE-TEST-CLIENT", server=self.server)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_challenge_nonce_lifecycle_and_single_use(self):
        # Obtain challenge nonce
        nonce_mgr = self.server.nonce_manager
        nonce = nonce_mgr.generate_nonce()
        self.assertEqual(len(nonce), 32)

        # First verify should succeed and burn
        self.assertTrue(nonce_mgr.verify_and_burn_nonce(nonce))

        # Replay attempt must fail
        self.assertFalse(nonce_mgr.verify_and_burn_nonce(nonce))

    def test_sas_derivation_and_pairing(self):
        self.client.run_feasibility_gate(tls_supported=True, crypto_supported=True, background_ok=True)
        
        # Check SAS consistency
        client_pub = self.client.identity.public_key
        server_pub = self.server.identity.public_key
        sas_client = self.client.identity.compute_sas_code(server_pub)
        sas_server = self.server.identity.compute_sas_code(client_pub)

        self.assertEqual(sas_client, sas_server)
        self.assertEqual(len(sas_client), 6)
        self.assertTrue(sas_client.isdigit())

        # Pairing without user confirmation must fail
        with self.assertRaises(MotoSecurityError):
            self.client.pair_device(pairing_code_confirmed=False)

        # Pairing with confirmation succeeds
        self.assertTrue(self.client.pair_device(pairing_code_confirmed=True))
        self.assertTrue(self.client.paired)
        self.assertTrue(self.server.identity.paired)

    def test_request_signature_verification(self):
        self.client.run_feasibility_gate()
        self.client.pair_device(pairing_code_confirmed=True)

        nonce = self.server.nonce_manager.generate_nonce()
        method = "POST"
        path = "/storage/v1/list"
        body = b'{"subfolder": ""}'

        sig = self.client.identity.sign_payload(nonce, method, path, body)
        self.assertTrue(self.server.identity.verify_signature(nonce, method, path, body, sig, self.client.identity.public_key))

        # Tampered body fails
        tampered_body = b'{"subfolder": "hacked"}'
        self.assertFalse(self.server.identity.verify_signature(nonce, method, path, tampered_body, sig, self.client.identity.public_key))

    def test_access_permission_gate_and_full_pipeline(self):
        self.client.run_feasibility_gate()
        self.client.pair_device(pairing_code_confirmed=True)

        # Create test file in jail
        test_file_path = os.path.join(self.temp_dir, "notes.txt")
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write("Project notes: Secret API key sk-1234567890abcdef123456 is active.")

        # Attempt to read without access permission MUST fail
        self.client.set_access_permission(False)
        with self.assertRaises(MotoSecurityError) as cm:
            self.client.read_file("notes.txt")
        self.assertIn("Access permission denied", str(cm.exception))

        # Grant access permission -> reading succeeds and runs through full pipeline
        self.client.set_access_permission(True)
        context = self.client.read_file("notes.txt")

        # Verify ScannedClassifiedContext output
        self.assertIsInstance(context, ScannedClassifiedContext)
        self.assertEqual(context.data_class, DataClass.PROTECTED)
        self.assertEqual(context.source, SourceDomain.MOTO_STORAGE)
        self.assertFalse(context.cloud_approved)
        self.assertTrue(context.scanned)
        self.assertTrue(context.scan_summary.get("healthy"))
        self.assertEqual(context.scan_summary.get("redaction_count"), 1)
        self.assertIn("[REDACTED:API_KEY]", context.content)
        self.assertNotIn("sk-1234567890abcdef123456", context.content)
        self.assertEqual(context.metadata.get("location_for_model"), "MOTO_STORAGE/notes.txt")

    def test_bounded_buffering_5mb_limit(self):
        self.client.run_feasibility_gate()
        self.client.pair_device(pairing_code_confirmed=True)
        self.client.set_access_permission(True)

        # Create oversized 6 MB file in jail
        large_file_path = os.path.join(self.temp_dir, "large.txt")
        with open(large_file_path, "wb") as f:
            f.write(b"A" * (6 * 1024 * 1024))

        with self.assertRaises(MotoSecurityError) as cm:
            self.client.read_file("large.txt")
        self.assertIn("5 MB", str(cm.exception))

    def test_revocation_purges_keys_and_halts_requests(self):
        self.client.run_feasibility_gate()
        self.client.pair_device(pairing_code_confirmed=True)
        self.client.set_access_permission(True)

        self.assertTrue(self.client.paired)
        self.client.revoke_pairing()
        self.assertFalse(self.client.paired)

        with self.assertRaises(MotoSecurityError):
            self.client.read_file("notes.txt")


if __name__ == "__main__":
    unittest.main()
