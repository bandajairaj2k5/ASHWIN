"""
ASHWIN Secure Provisioning Package Engine (Phase 2, Section 7, Section 12, RULE-02).
Implements versioned, PBKDF2-HMAC-SHA256 (600k iter) + AES-256-GCM package creation,
strict certificate validation, metadata binding, and anti-replay parsing.
"""

import os
import json
import time
import uuid
import hashlib
from typing import Dict, Any, Tuple, Optional, Set
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class ProvisioningError(Exception):
    """Raised for package format, authentication, expiration, or certificate validation errors."""
    pass


class ProvisioningPackageEngine:
    MAGIC = b"ASHWINPR"          # 8 bytes
    FORMAT_VERSION_1 = b"\x00\x01" # 2 bytes
    PBKDF2_ITERATIONS = 600_000   # 600k iterations per security design
    DEFAULT_TTL_SECONDS = 86_400  # 24 hours configurable default

    @classmethod
    def compute_cert_fingerprint(cls, cert_pem: str) -> str:
        """Computes SHA-256 fingerprint hex of an X.509 certificate in PEM format."""
        clean_pem = cert_pem.strip()
        cert = x509.load_pem_x509_certificate(clean_pem.encode("utf-8"))
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    @classmethod
    def create_package(
        cls,
        pin: str,
        ca_cert_pem: str,
        client_cert_pem: str,
        client_key_pem: str,
        server_cert_pem: Optional[str] = None,
        endpoint_host: str = "10.202.197.15",
        endpoint_port: int = 8443,
        endpoint_use_tls: bool = True,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        package_id: Optional[str] = None
    ) -> bytes:
        """
        Creates an encrypted, authenticated ASHWIN-PROV-1.0 binary provisioning artifact.
        """
        if not pin or len(pin) < 4:
            raise ProvisioningError("Setup PIN must be at least 4 characters.")

        # Strict Pre-Pack Validation
        cls.validate_credentials_in_memory(ca_cert_pem, client_cert_pem, client_key_pem)

        pkg_id = package_id or str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + ttl_seconds

        ca_fp = cls.compute_cert_fingerprint(ca_cert_pem)
        client_fp = cls.compute_cert_fingerprint(client_cert_pem)
        server_fp = cls.compute_cert_fingerprint(server_cert_pem) if server_cert_pem else ""

        payload_dict = {
            "metadata": {
                "format_version": "ASHWIN-PROV-1.0",
                "package_id": pkg_id,
                "protocol_version": "ASHWIN-MOTO-V0.1",
                "intended_endpoint_id": "MOTO-G3-01",
                "endpoint_host": endpoint_host,
                "endpoint_port": endpoint_port,
                "endpoint_use_tls": endpoint_use_tls,
                "ca_cert_fingerprint_sha256": ca_fp,
                "client_cert_fingerprint_sha256": client_fp,
                "server_cert_fingerprint_sha256": server_fp,
                "created_at": now,
                "expires_at": expires_at
            },
            "credentials": {
                "ca_cert_pem": ca_cert_pem.strip(),
                "client_cert_pem": client_cert_pem.strip(),
                "client_key_pem": client_key_pem.strip()
            }
        }

        payload_bytes = json.dumps(payload_dict, indent=2).encode("utf-8")

        # Key derivation
        salt = os.urandom(32)
        iv = os.urandom(12)
        key = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, cls.PBKDF2_ITERATIONS, dklen=32)

        # Authenticated Additional Data binds header to ciphertext
        aad = cls.MAGIC + cls.FORMAT_VERSION_1

        aesgcm = AESGCM(key)
        ciphertext_and_tag = aesgcm.encrypt(iv, payload_bytes, aad)

        # Wire: MAGIC (8B) + VERSION (2B) + SALT (32B) + IV (12B) + CIPHERTEXT+TAG
        return cls.MAGIC + cls.FORMAT_VERSION_1 + salt + iv + ciphertext_and_tag

    @classmethod
    def decrypt_and_validate_package(
        cls,
        package_bytes: bytes,
        pin: str,
        consumed_package_ids: Optional[Set[str]] = None,
        current_time: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Decrypts, authenticates, validates, and unpacks the provisioning package.
        Enforces:
        - Magic bytes & format versioning
        - AES-GCM tag verification (PIN correctness)
        - Anti-replay (consumed package ID check)
        - Expiration TTL check
        - Strict X.509 cert and RSA private key validation (cert validity, keypair match, fingerprint match)
        """
        min_header_len = 8 + 2 + 32 + 12 + 16 # 70 bytes minimum
        if len(package_bytes) < min_header_len:
            raise ProvisioningError("Invalid package: Truncated binary header.")

        magic = package_bytes[0:8]
        if magic != cls.MAGIC:
            raise ProvisioningError("Invalid package: Missing ASHWINPR magic header.")

        version = package_bytes[8:10]
        if version != cls.FORMAT_VERSION_1:
            raise ProvisioningError(f"Unsupported format version: {version.hex()}")

        salt = package_bytes[10:42]
        iv = package_bytes[42:54]
        ciphertext_and_tag = package_bytes[54:]

        # Derive Key
        key = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, cls.PBKDF2_ITERATIONS, dklen=32)
        aad = cls.MAGIC + cls.FORMAT_VERSION_1

        aesgcm = AESGCM(key)
        try:
            payload_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, aad)
        except Exception as e:
            raise ProvisioningError("Package decryption failed: Incorrect Setup PIN or corrupted package.") from e

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            raise ProvisioningError("Invalid package payload: JSON parse error.") from e

        metadata = payload.get("metadata", {})
        credentials = payload.get("credentials", {})

        pkg_id = metadata.get("package_id")
        if not pkg_id:
            raise ProvisioningError("Missing package_id in metadata.")

        # Replay check
        if consumed_package_ids and pkg_id in consumed_package_ids:
            raise ProvisioningError(f"Security Rejection: Package {pkg_id} has already been consumed.")

        # Expiration check
        now = current_time if current_time is not None else int(time.time())
        expires_at = metadata.get("expires_at", 0)
        if now > expires_at:
            raise ProvisioningError(f"Security Rejection: Provisioning package expired at {expires_at} (current {now}).")

        # Strict Certificate & Key Validation
        ca_pem = credentials.get("ca_cert_pem", "")
        client_cert_pem = credentials.get("client_cert_pem", "")
        client_key_pem = credentials.get("client_key_pem", "")

        cls.validate_credentials_in_memory(ca_pem, client_cert_pem, client_key_pem)

        # Fingerprint checks against metadata
        if metadata.get("ca_cert_fingerprint_sha256"):
            if cls.compute_cert_fingerprint(ca_pem) != metadata["ca_cert_fingerprint_sha256"]:
                raise ProvisioningError("CA certificate fingerprint mismatch against metadata.")

        if metadata.get("client_cert_fingerprint_sha256"):
            if cls.compute_cert_fingerprint(client_cert_pem) != metadata["client_cert_fingerprint_sha256"]:
                raise ProvisioningError("Client certificate fingerprint mismatch against metadata.")

        return payload

    @classmethod
    def validate_credentials_in_memory(cls, ca_pem: str, client_cert_pem: str, client_key_pem: str):
        """
        Validates:
        1. Valid X.509 format and non-expired certificates.
        2. Expected RSA key algorithms and minimum 2048-bit key size.
        3. Client certificate public key matches the client private key.
        """
        if not ca_pem or not client_cert_pem or not client_key_pem:
            raise ProvisioningError("Missing required certificate or private key PEM material.")

        # 1. Parse CA Cert
        try:
            ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
        except Exception as e:
            raise ProvisioningError(f"Invalid CA certificate PEM: {e}")

        # 2. Parse Client Cert
        try:
            client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode("utf-8"))
        except Exception as e:
            raise ProvisioningError(f"Invalid Client certificate PEM: {e}")

        # 3. Check Validity Periods (now within not_valid_before and not_valid_after)
        # Note: Using standard datetime comparison
        now_dt = time.time()
        ca_not_before = ca_cert.not_valid_before_utc.timestamp()
        ca_not_after = ca_cert.not_valid_after_utc.timestamp()
        if now_dt < ca_not_before or now_dt > ca_not_after:
            raise ProvisioningError("CA certificate is not valid at current time.")

        cl_not_before = client_cert.not_valid_before_utc.timestamp()
        cl_not_after = client_cert.not_valid_after_utc.timestamp()
        if now_dt < cl_not_before or now_dt > cl_not_after:
            raise ProvisioningError("Client certificate is not valid at current time.")

        # 4. Parse Client Private Key
        try:
            priv_key = serialization.load_pem_private_key(client_key_pem.encode("utf-8"), password=None)
        except Exception as e:
            raise ProvisioningError(f"Invalid Client private key PEM: {e}")

        # 5. Algorithm & Size Validation (Require RSA >= 2048)
        if not isinstance(priv_key, rsa.RSAPrivateKey):
            raise ProvisioningError("Expected RSA private key algorithm.")
        if priv_key.key_size < 2048:
            raise ProvisioningError(f"Insecure key size: RSA {priv_key.key_size} is less than required 2048 bits.")

        # 6. Cryptographic Pair Match Verification (Verify public key matches private key)
        cert_pub_key = client_cert.public_key()
        if not isinstance(cert_pub_key, rsa.RSAPublicKey):
            raise ProvisioningError("Client certificate does not contain an RSA public key.")

        if cert_pub_key.public_numbers() != priv_key.public_key().public_numbers():
            raise ProvisioningError("Cryptographic mismatch: Client certificate public key does not match client private key.")

        # Verification via test signature
        test_msg = b"ASHWIN_KEYPAIR_VALIDATION"
        sig = priv_key.sign(test_msg, padding.PKCS1v15(), hashes.SHA256())
        try:
            cert_pub_key.verify(sig, test_msg, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise ProvisioningError("Cryptographic signature verification failed between private key and certificate.") from e
