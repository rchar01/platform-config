#!/usr/bin/env python3
import argparse
import hashlib
import http.server
import json
import ssl
from pathlib import Path
from typing import cast


class FixtureServer(http.server.ThreadingHTTPServer):
    allowed_paths: tuple[str, ...]
    expected_host: str
    node: str
    status_file: Path
    sni_log: Path


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self):
        server = cast(FixtureServer, self.server)
        if self.headers.get("Host") != server.expected_host:
            self.send_response(421)
            self.end_headers()
            return
        if server.allowed_paths and self.path not in server.allowed_paths:
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(content_length)
        status = int(server.status_file.read_text(encoding="ascii").strip())
        peer_subject = dict(
            attribute
            for relative_name in self.connection.getpeercert().get("subject", ())
            for attribute in relative_name
        )
        body = json.dumps(
            {
                "client_cn": peer_subject.get("commonName"),
                "authorization": self.headers.get("Authorization"),
                "host": self.headers.get("Host"),
                "method": self.command,
                "node": server.node,
                "path": self.path,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "tenant": self.headers.get("X-Scope-OrgID"),
                "x_amz_content_sha256": self.headers.get("X-Amz-Content-Sha256"),
                "x_amz_date": self.headers.get("X-Amz-Date"),
            },
            separators=(",", ":"),
        ).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_DELETE = _respond
    do_HEAD = _respond
    do_OPTIONS = _respond
    do_PATCH = _respond
    do_POST = _respond
    do_PUT = _respond

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--allowed-path", action="append", default=[])
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--sni-log", required=True)
    args = parser.parse_args()

    server = FixtureServer((args.bind, args.port), FixtureHandler)
    server.allowed_paths = tuple(args.allowed_path)
    server.expected_host = args.expected_host
    server.node = args.node
    server.status_file = Path(args.status_file)
    server.sni_log = Path(args.sni_log)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED

    def record_sni(_socket, server_name, _context):
        with server.sni_log.open("a", encoding="ascii") as log:
            log.write(f"{server_name}\n")

    context.set_servername_callback(record_sni)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
