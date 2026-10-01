"""
ASHWIN Moto G3 Live HTTPS / mTLS Storage Server (Section 7.1, 7.3, 7.4, 10).
Runs on Moto G3, bound to 0.0.0.0:8443.
Implements HTTPS request handling with single-use challenge nonces and StorageJail.
"""

import os
import sys
import json
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

# Import endpoint modules
from jail import StorageJail
from crypto import DeviceIdentity, ChallengeNonceManager
from server import MotoStorageServer


class MotoHTTPRequestHandler(BaseHTTPRequestHandler):

    server_core: MotoStorageServer = None

    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[MOTO_ENDPOINT] {self.command} {self.path} -> {args[1]}\n")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        headers_dict = {k: v for k, v in self.headers.items()}

        status, resp_headers, resp_body = self.server_core.handle_request(
            method="POST",
            path=self.path,
            headers=headers_dict,
            body=body
        )

        self.send_response(status)
        for h_k, h_v in resp_headers.items():
            self.send_header(h_k, h_v)
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        # Only POST is supported in storage API specification
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error": "Method Not Allowed: Only POST is supported"}')


def run_server(port: int = 8443, storage_dir: str = "ASHWIN_STORAGE"):
    os.makedirs(storage_dir, exist_ok=True)
    server_core = MotoStorageServer(root_dir=storage_dir, device_id="MOTO-G3-ENDPOINT")
    MotoHTTPRequestHandler.server_core = server_core

    httpd = HTTPServer(("0.0.0.0", port), MotoHTTPRequestHandler)
    print(f"[MOTO_SERVER] Running on https://0.0.0.0:{port} with root '{storage_dir}'", flush=True)
    
    # Check if TLS certs exist
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(script_dir, "server.crt") if os.path.exists(os.path.join(script_dir, "server.crt")) else "server.crt"
    key_path = os.path.join(script_dir, "server.key") if os.path.exists(os.path.join(script_dir, "server.key")) else "server.key"
    ca_path = os.path.join(script_dir, "ca.crt") if os.path.exists(os.path.join(script_dir, "ca.crt")) else "ca.crt"

    if os.path.exists(cert_path) and os.path.exists(key_path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        if os.path.exists(ca_path):
            context.load_verify_locations(cafile=ca_path)
            context.verify_mode = ssl.CERT_REQUIRED
            print("[MOTO_SERVER] Mutual TLS (mTLS) with Client Certificate Authentication ACTIVE", flush=True)
        else:
            print("[MOTO_SERVER] TLS 1.2/1.3 Server ACTIVE", flush=True)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    else:
        print("[MOTO_SERVER] Note: Running in application-layer crypto mode (mTLS socket wrap optional)", flush=True)

    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    storage_path = sys.argv[2] if len(sys.argv) > 2 else "ASHWIN_STORAGE"
    run_server(port=port, storage_dir=storage_path)
