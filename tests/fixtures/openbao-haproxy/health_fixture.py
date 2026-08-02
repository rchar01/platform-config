#!/usr/bin/env python3
import argparse
import http.server
import json
import ssl
from pathlib import Path
from typing import cast


class HealthServer(http.server.ThreadingHTTPServer):
    expected_host: str
    node: str
    status_file: Path
    sni_log: Path


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        server = cast(HealthServer, self.server)
        if self.path != "/v1/sys/health":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("Host") != server.expected_host:
            self.send_response(421)
            self.end_headers()
            return

        status = int(server.status_file.read_text(encoding="ascii").strip())
        body = json.dumps(
            {
                "initialized": status != 501,
                "sealed": status == 503,
                "standby": status == 429,
                "node": server.node,
            },
            separators=(",", ":"),
        ).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--sni-log", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--expected-sni", action="append", required=True)
    args = parser.parse_args()

    server = HealthServer((args.bind, args.port), HealthHandler)
    server.expected_host = args.expected_host
    server.node = args.node
    server.status_file = Path(args.status_file)
    server.sni_log = Path(args.sni_log)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)

    def require_sni(_socket, server_name, _context):
        with server.sni_log.open("a", encoding="ascii") as log:
            log.write(f"{server_name}\n")
        if server_name not in args.expected_sni:
            raise ssl.SSLError("unexpected SNI")

    context.set_servername_callback(require_sni)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
