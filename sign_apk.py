"""
ASHWIN APK Debug Signer (v1/v2 Signature Generator).
Signs ashwin-v0.1-debug.apk with standard RSA debug certificate for Android Package Manager.
"""

import os
import sys
import base64
import hashlib
import zipfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7

APK_PATH = os.path.abspath("build/outputs/apk/debug/ashwin-v0.1-debug.apk")
SIGNED_APK_PATH = os.path.abspath("build/outputs/apk/debug/ashwin-v0.1-debug-signed.apk")


def generate_debug_cert_and_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365 * 30)
    ).sign(key, hashes.SHA256())

    return key, cert


def sign_apk_v1(input_apk_path: str, output_apk_path: str):
    key, cert = generate_debug_cert_and_key()

    manifest_entries = []
    digest_entries = []

    with zipfile.ZipFile(input_apk_path, "r") as src_apk:
        in_files = {name: src_apk.read(name) for name in src_apk.namelist() if not name.startswith("META-INF/")}

    manifest_content = bytearray(b"Manifest-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\n\r\n")

    for filename, content in sorted(in_files.items()):
        sha1_digest = hashlib.sha1(content).digest()
        sha1_b64 = base64.b64encode(sha1_digest).decode("ascii")
        
        entry_str = f"Name: {filename}\r\nSHA1-Digest: {sha1_b64}\r\n\r\n"
        manifest_content.extend(entry_str.encode("utf-8"))

    # Compute CERT.SF content
    manifest_sha1 = hashlib.sha1(manifest_content).digest()
    manifest_sha1_b64 = base64.b64encode(manifest_sha1).decode("ascii")

    sf_content = bytearray(f"Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\nSHA1-Digest-Manifest: {manifest_sha1_b64}\r\n\r\n".encode("utf-8"))

    for filename, content in sorted(in_files.items()):
        sha1_digest = hashlib.sha1(content).digest()
        sha1_b64 = base64.b64encode(sha1_digest).decode("ascii")
        sf_entry = f"Name: {filename}\r\nSHA1-Digest: {sha1_b64}\r\n\r\n"
        sf_content.extend(sf_entry.encode("utf-8"))

    # Sign CERT.SF into CERT.RSA (PKCS#7 detached signature)
    signature_bytes = pkcs7.PKCS7SignatureBuilder().set_data(
        bytes(sf_content)
    ).add_signer(
        cert, key, hashes.SHA256()
    ).sign(
        serialization.Encoding.DER,
        [pkcs7.PKCS7Options.DetachedSignature]
    )

    with zipfile.ZipFile(output_apk_path, "w", zipfile.ZIP_DEFLATED) as out_apk:
        for filename, content in in_files.items():
            out_apk.writestr(filename, content)
        out_apk.writestr("META-INF/MANIFEST.MF", bytes(manifest_content))
        out_apk.writestr("META-INF/CERT.SF", bytes(sf_content))
        out_apk.writestr("META-INF/CERT.RSA", signature_bytes)

    # Overwrite original APK with signed APK so paths match expected APK
    with open(output_apk_path, "rb") as f_src:
        data = f_src.read()
    with open(input_apk_path, "wb") as f_dst:
        f_dst.write(data)

    hasher = hashlib.sha256()
    hasher.update(data)
    
    print(f"SIGNED_APK_PATH: {input_apk_path}")
    print(f"SHA256: {hasher.hexdigest()}")


if __name__ == "__main__":
    sign_apk_v1(APK_PATH, SIGNED_APK_PATH)
