#!/usr/bin/env python3
import argparse
import http.server
import ssl
from typing import cast


class ProbeServer(http.server.ThreadingHTTPServer):
    expected_host: str


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        server = cast(ProbeServer, self.server)
        if self.headers.get("Host") != server.expected_host:
            self.send_response(421)
            self.end_headers()
            self.wfile.write(b"wrong host\n")
            return

        if self.path == "/ready":
            self.send_response(200)
            body = b"ready\n"
        elif self.path == "/ready-wrong-body":
            self.send_response(200)
            body = b"starting\n"
        elif self.path == "/api/health":
            self.send_response(200)
            body = b'{"database":"ok","version":"13.1.3"}\n'
        elif self.path == "/api/health-degraded":
            self.send_response(200)
            body = b'{"database":"failed","version":"13.1.3"}\n'
        elif self.path == "/api/health-wrong-version":
            self.send_response(200)
            body = b'{"database":"ok","version":"13.1.30"}\n'
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ready")
            body = b"ready\n"
        elif self.path == "/status":
            self.send_response(503)
            body = b"ready\n"
        elif self.path == "/missing-body":
            self.send_response(200)
            body = b"starting\n"
        elif self.path == "/forbidden-body":
            self.send_response(200)
            body = b"ready failed\n"
        else:
            self.send_response(404)
            body = b"not found\n"

        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca")
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--expected-sni", required=True)
    args = parser.parse_args()

    server = ProbeServer(("127.0.0.1", args.port), ProbeHandler)
    server.expected_host = args.expected_host
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    if args.client_ca:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(args.client_ca)

    def require_sni(_socket, server_name, _context):
        if server_name != args.expected_sni:
            raise ssl.SSLError("unexpected SNI")

    context.set_servername_callback(require_sni)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
