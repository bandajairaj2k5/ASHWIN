"""
Unit tests for ASHWIN Secure Provisioning Engine (Phase 2, Section 7, Section 12, RULE-02).
"""

import unittest
import os
import json
import time
import hashlib
from ashwin.core.provisioning import ProvisioningPackageEngine, ProvisioningError
from ashwin.core.credentials import CredentialStore
from ashwin.core.endpoint_config import EndpointConfig
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


class TestProvisioningPackageEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load real test certificates
        with open("certs/ca.crt", "r", encoding="utf-8") as f:
            cls.ca_pem = f.read()
        with open("certs/client.crt", "r", encoding="utf-8") as f:
            cls.client_cert_pem = f.read()
        with open("certs/client.key", "r", encoding="utf-8") as f:
            cls.client_key_pem = f.read()
        with open("certs/server.crt", "r", encoding="utf-8") as f:
            cls.server_cert_pem = f.read()

        cls.pin = "AshwinSetupPin2026!"

    def test_positive_package_creation_and_decryption(self):
        pkg_bytes = ProvisioningPackageEngine.create_package(
            pin=self.pin,
            ca_cert_pem=self.ca_pem,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem,
            server_cert_pem=self.server_cert_pem,
            endpoint_host="10.202.197.15",
            endpoint_port=8443,
            ttl_seconds=3600
        )

        self.assertTrue(pkg_bytes.startswith(b"ASHWINPR\x00\x01"))
        self.assertGreater(len(pkg_bytes), 2000)

        # Decrypt with correct PIN
        payload = ProvisioningPackageEngine.decrypt_and_validate_package(
            package_bytes=pkg_bytes,
            pin=self.pin,
            consumed_package_ids=set(),
            current_time=int(time.time())
        )

        self.assertEqual(payload["metadata"]["format_version"], "ASHWIN-PROV-1.0")
        self.assertEqual(payload["metadata"]["intended_endpoint_id"], "MOTO-G3-01")
        self.assertEqual(payload["metadata"]["endpoint_host"], "10.202.197.15")
        self.assertEqual(payload["credentials"]["ca_cert_pem"], self.ca_pem.strip())
        self.assertEqual(payload["credentials"]["client_cert_pem"], self.client_cert_pem.strip())

    def test_wrong_pin_fails_authentication(self):
        pkg_bytes = ProvisioningPackageEngine.create_package(
            pin=self.pin,
            ca_cert_pem=self.ca_pem,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem
        )

        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.decrypt_and_validate_package(
                package_bytes=pkg_bytes,
                pin="WrongPassword123!",
                consumed_package_ids=set()
            )
        self.assertIn("Incorrect Setup PIN", str(cm.exception))

    def test_anti_replay_consumed_package_rejection(self):
        pkg_bytes = ProvisioningPackageEngine.create_package(
            pin=self.pin,
            ca_cert_pem=self.ca_pem,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem,
            package_id="test-pkg-id-12345"
        )

        # First consumption
        consumed_set = set()
        payload = ProvisioningPackageEngine.decrypt_and_validate_package(
            package_bytes=pkg_bytes,
            pin=self.pin,
            consumed_package_ids=consumed_set
        )
        pkg_id = payload["metadata"]["package_id"]
        self.assertEqual(pkg_id, "test-pkg-id-12345")
        consumed_set.add(pkg_id)

        # Second consumption must fail
        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.decrypt_and_validate_package(
                package_bytes=pkg_bytes,
                pin=self.pin,
                consumed_package_ids=consumed_set
            )
        self.assertIn("already been consumed", str(cm.exception))

    def test_ttl_expiration_rejection(self):
        now = int(time.time())
        pkg_bytes = ProvisioningPackageEngine.create_package(
            pin=self.pin,
            ca_cert_pem=self.ca_pem,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem,
            ttl_seconds=300 # 5 min TTL
        )

        # Attempt after 301 seconds
        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.decrypt_and_validate_package(
                package_bytes=pkg_bytes,
                pin=self.pin,
                current_time=now + 301
            )
        self.assertIn("expired", str(cm.exception))

    def test_tamper_detection_on_header_or_ciphertext(self):
        pkg_bytes = bytearray(ProvisioningPackageEngine.create_package(
            pin=self.pin,
            ca_cert_pem=self.ca_pem,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem
        ))

        # Tamper one byte in ciphertext
        pkg_bytes[-5] ^= 0xFF

        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.decrypt_and_validate_package(
                package_bytes=bytes(pkg_bytes),
                pin=self.pin
            )
        self.assertIn("corrupted package", str(cm.exception))

    def test_keypair_mismatch_rejection(self):
        # Generate another independent RSA keypair
        mismatched_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mismatched_key_pem = mismatched_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        # Package creation should reject keypair mismatch
        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.create_package(
                pin=self.pin,
                ca_cert_pem=self.ca_pem,
                client_cert_pem=self.client_cert_pem,
                client_key_pem=mismatched_key_pem # mismatched
            )
        self.assertIn("Cryptographic mismatch", str(cm.exception))

    def test_weak_rsa_key_size_rejection(self):
        # Generate weak 1024-bit key
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        weak_key_pem = weak_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        # Self-sign weak cert
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"WeakClient")])
        weak_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            weak_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(weak_key, hashes.SHA256())

        weak_cert_pem = weak_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        with self.assertRaises(ProvisioningError) as cm:
            ProvisioningPackageEngine.create_package(
                pin=self.pin,
                ca_cert_pem=self.ca_pem,
                client_cert_pem=weak_cert_pem,
                client_key_pem=weak_key_pem
            )
        self.assertIn("Insecure key size", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
