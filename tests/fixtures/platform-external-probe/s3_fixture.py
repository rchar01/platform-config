#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import http.server
import json
import ssl
import time
from pathlib import Path
from typing import cast


class S3Server(http.server.ThreadingHTTPServer):
    access_key_id: str
    secret_access_key: str
    region: str
    expected_host: str
    expected_path: str
    state_file: Path
    object_body: bytes | None = None


def sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


class S3Handler(http.server.BaseHTTPRequestHandler):
    def verify_signature(self, body: bytes) -> bool:
        server = cast(S3Server, self.server)
        authorization = self.headers.get("Authorization", "")
        amz_date = self.headers.get("X-Amz-Date", "")
        payload_hash = hashlib.sha256(body).hexdigest()
        if self.headers.get("Host") != server.expected_host:
            return False
        if self.path != server.expected_path:
            return False
        if self.headers.get("X-Amz-Content-Sha256") != payload_hash:
            return False
        date_stamp = amz_date[:8]
        scope = f"{date_stamp}/{server.region}/s3/aws4_request"
        prefix = f"AWS4-HMAC-SHA256 Credential={server.access_key_id}/{scope}, "
        middle = "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        if not authorization.startswith(prefix + middle):
            return False
        signature = authorization.removeprefix(prefix + middle)
        canonical_headers = (
            f"host:{server.expected_host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        canonical_request = "\n".join(
            [
                self.command,
                self.path,
                "",
                canonical_headers,
                "host;x-amz-content-sha256;x-amz-date",
                payload_hash,
            ]
        )
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        date_key = sign(("AWS4" + server.secret_access_key).encode(), date_stamp)
        region_key = sign(date_key, server.region)
        service_key = sign(region_key, "s3")
        signing_key = sign(service_key, "aws4_request")
        expected = hmac.new(
            signing_key, string_to_sign.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def state(self) -> str:
        return cast(S3Server, self.server).state_file.read_text().strip()

    def respond(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if not self.verify_signature(body):
            self.respond(403)
            return
        if self.state() == "put-failure":
            self.respond(503)
            return
        cast(S3Server, self.server).object_body = body
        self.respond(200)

    def do_GET(self) -> None:
        if not self.verify_signature(b""):
            self.respond(403)
            return
        server = cast(S3Server, self.server)
        body = server.object_body or b""
        if self.state() == "slow-header":
            time.sleep(4)
        if self.state() == "mismatch":
            body = b"wrong payload\n"
        if self.state() == "oversized":
            body = body + b"x"
        if self.state() == "trickle":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for byte in body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(1)
            return
        self.respond(200, body)

    def do_DELETE(self) -> None:
        if not self.verify_signature(b""):
            self.respond(403)
            return
        server = cast(S3Server, self.server)
        if self.state() == "delete-failure" and server.object_body is not None:
            self.respond(503)
            return
        server.object_body = None
        self.respond(204)

    def log_message(self, format, *args):
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-path", required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()
    credentials = json.loads(Path(args.credentials).read_text())
    server = S3Server(("127.0.0.1", args.port), S3Handler)
    server.access_key_id = credentials["access_key_id"]
    server.secret_access_key = credentials["secret_access_key"]
    server.region = args.region
    server.expected_host = args.expected_host
    server.expected_path = args.expected_path
    server.state_file = Path(args.state_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(args.client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
