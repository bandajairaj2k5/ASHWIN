"""
Host Administrator CLI Tool for ASHWIN Secure Credential Packaging.
Packages ca.crt, client.crt, client.key, and EndpointConfig into an encrypted ASHWIN-PROV-1.0 artifact.
"""

import os
import sys
import argparse

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ashwin.core.provisioning import ProvisioningPackageEngine, ProvisioningError


def main():
    parser = argparse.ArgumentParser(description="Create encrypted ASHWIN provisioning package for Moto G3 identity.")
    parser.add_argument("--ca-cert", default="certs/ca.crt", help="Path to ca.crt")
    parser.add_argument("--client-cert", default="certs/client.crt", help="Path to client.crt")
    parser.add_argument("--client-key", default="certs/client.key", help="Path to client.key")
    parser.add_argument("--server-cert", default="certs/server.crt", help="Path to server.crt (optional for fingerprint binding)")
    parser.add_argument("--host", default="10.202.197.15", help="Moto G3 endpoint IP/hostname")
    parser.add_argument("--port", type=int, default=8443, help="Moto G3 endpoint port")
    parser.add_argument("--pin", required=True, help="Setup PIN for AES-256-GCM encryption")
    parser.add_argument("--output", default="ashwin_identity.bin", help="Output binary package path")
    parser.add_argument("--ttl", type=int, default=86400, help="Package validity TTL in seconds (default: 86400 / 24h)")

    args = parser.parse_args()

    for path, name in [(args.ca_cert, "CA Certificate"), (args.client_cert, "Client Certificate"), (args.client_key, "Client Private Key")]:
        if not os.path.exists(path):
            print(f"Error: {name} file '{path}' not found.", file=sys.stderr)
            sys.exit(1)

    with open(args.ca_cert, "r", encoding="utf-8") as f:
        ca_pem = f.read()
    with open(args.client_cert, "r", encoding="utf-8") as f:
        client_cert_pem = f.read()
    with open(args.client_key, "r", encoding="utf-8") as f:
        client_key_pem = f.read()

    server_cert_pem = None
    if os.path.exists(args.server_cert):
        with open(args.server_cert, "r", encoding="utf-8") as f:
            server_cert_pem = f.read()

    try:
        package_bytes = ProvisioningPackageEngine.create_package(
            pin=args.pin,
            ca_cert_pem=ca_pem,
            client_cert_pem=client_cert_pem,
            client_key_pem=client_key_pem,
            server_cert_pem=server_cert_pem,
            endpoint_host=args.host,
            endpoint_port=args.port,
            endpoint_use_tls=True,
            ttl_seconds=args.ttl
        )
    except ProvisioningError as pe:
        print(f"Packaging failed validation: {pe}", file=sys.stderr)
        sys.exit(2)

    with open(args.output, "wb") as f:
        f.write(package_bytes)

    print(f"Successfully generated encrypted provisioning package: {args.output} ({len(package_bytes)} bytes)")
    print(f"Format: ASHWIN-PROV-1.0 (PBKDF2-HMAC-SHA256 600,000 iter + AES-256-GCM)")
    print(f"Target Moto Endpoint: {args.host}:{args.port}")
    print(f"TTL: {args.ttl} seconds")


if __name__ == "__main__":
    main()
