"""
ASHWIN Standard APK Debug Signer.
Signs ashwin-v0.1-debug.apk with standard RSA debug certificate for Android 16.
"""

import os
import sys
import base64
import hashlib
import zipfile
import subprocess
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

APK_PATH = os.path.abspath("build/outputs/apk/debug/ashwin-v0.1-debug.apk")
KEYSTORE_PATH = os.path.abspath("debug.keystore")


def sign_apk():
    # Build unsigned base APK first
    from build_axml import build_and_package_apk
    build_and_package_apk()

    # Load key and cert from keytool keystore or cryptography
    with zipfile.ZipFile(APK_PATH, "r") as src:
        in_files = {name: src.read(name) for name in src.namelist() if not name.startswith("META-INF/")}

    manifest_content = bytearray(b"Manifest-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\n\r\n")

    for filename, content in sorted(in_files.items()):
        sha1_digest = hashlib.sha1(content).digest()
        sha1_b64 = base64.b64encode(sha1_digest).decode("ascii")
        entry_str = f"Name: {filename}\r\nSHA1-Digest: {sha1_b64}\r\n\r\n"
        manifest_content.extend(entry_str.encode("utf-8"))

    manifest_sha1 = hashlib.sha1(manifest_content).digest()
    manifest_sha1_b64 = base64.b64encode(manifest_sha1).decode("ascii")

    sf_content = bytearray(f"Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\nSHA1-Digest-Manifest: {manifest_sha1_b64}\r\n\r\n".encode("utf-8"))

    for filename, content in sorted(in_files.items()):
        sha1_digest = hashlib.sha1(content).digest()
        sha1_b64 = base64.b64encode(sha1_digest).decode("ascii")
        sf_entry = f"Name: {filename}\r\nSHA1-Digest: {sha1_b64}\r\n\r\n"
        sf_content.extend(sf_entry.encode("utf-8"))

    # Generate RSA key & self-signed cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * 30)).sign(key, hashes.SHA256())

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    # Calculate SHA256withRSA signature over sf_content
    sig = key.sign(bytes(sf_content), padding.PKCS1v15(), hashes.SHA256())

    # Build clean PKCS7 SignedData DER structure without SMIME capability extension
    # OID 1.2.840.113549.1.7.2 (signedData)
    # OID 1.2.840.113549.1.7.1 (data)
    # OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    # OID 2.16.840.1.101.3.4.2.1 (sha256)

    def der_tlv(tag: int, val: bytes) -> bytes:
        length = len(val)
        if length < 128:
            len_bytes = bytes([length])
        elif length < 256:
            len_bytes = bytes([0x81, length])
        else:
            len_bytes = bytes([0x82, length >> 8, length & 0xFF])
        return bytes([tag]) + len_bytes + val

    def der_seq(items: list) -> bytes:
        return der_tlv(0x30, b"".join(items))

    def der_set(items: list) -> bytes:
        return der_tlv(0x31, b"".join(items))

    def der_oid(oid_str: str) -> bytes:
        parts = [int(p) for p in oid_str.split(".")]
        octets = [parts[0] * 40 + parts[1]]
        for p in parts[2:]:
            val = p
            buf = []
            while True:
                buf.append((val & 0x7F) | (0x80 if buf else 0))
                val >>= 7
                if val == 0:
                    break
            octets.extend(reversed(buf))
        return der_tlv(0x06, bytes(octets))

    oid_signedData = der_oid("1.2.840.113549.1.7.2")
    oid_data = der_oid("1.2.840.113549.1.7.1")
    oid_sha256 = der_oid("2.16.840.1.101.3.4.2.1")
    oid_rsa_sha256 = der_oid("1.2.840.113549.1.1.11")

    digest_algo_set = der_set([der_seq([oid_sha256, b"\x05\x00"])])
    encap_content_info = der_seq([oid_data])

    # Certificate set
    cert_set = der_tlv(0xA0, cert_der)

    # SignerInfo
    # Issuer & Serial
    issuer_der = cert.issuer.public_bytes(serialization.Encoding.DER)
    serial_der = der_tlv(0x02, cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8, 'big'))
    issuer_and_serial = der_seq([issuer_der, serial_der])

    signer_info = der_seq([
        der_tlv(0x02, b"\x01"), # version 1
        issuer_and_serial,
        der_seq([oid_sha256, b"\x05\x00"]),
        der_seq([oid_rsa_sha256, b"\x05\x00"]),
        der_tlv(0x04, sig)
    ])

    signer_infos_set = der_set([signer_info])

    signed_data = der_seq([
        der_tlv(0x02, b"\x01"), # version 1
        digest_algo_set,
        encap_content_info,
        cert_set,
        signer_infos_set
    ])

    content_info = der_seq([
        oid_signedData,
        der_tlv(0xA0, signed_data)
    ])

    with zipfile.ZipFile(APK_PATH, "w", zipfile.ZIP_DEFLATED) as out:
        for filename, content in in_files.items():
            out.writestr(filename, content)
        out.writestr("META-INF/MANIFEST.MF", bytes(manifest_content))
        out.writestr("META-INF/CERT.SF", bytes(sf_content))
        out.writestr("META-INF/CERT.RSA", content_info)

    hasher = hashlib.sha256()
    with open(APK_PATH, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)

    print(f"APK_PATH: {APK_PATH}")
    print(f"SHA256: {hasher.hexdigest()}")


if __name__ == "__main__":
    sign_apk()
