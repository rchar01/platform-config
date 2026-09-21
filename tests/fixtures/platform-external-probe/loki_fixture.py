#!/usr/bin/env python3
"""Disposable native Alloy sender checks, NOT Loki storage qualification.

Only loopback traffic and this container's synthetic journal are used. Evidence
retains body hashes and fixture markers, never full journal bodies or key bytes.
The bounded Snappy/protobuf decoder checks actual entries, not compressed-byte
substring matches. No third-party decoder/package download is needed.
The TLS12 field is checked in the rendered config and accepted by native Alloy;
the strict server proves interoperability, not rejection of an obsolete-only peer.
"""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import threading
import time
from typing import cast
import urllib.error
import urllib.request
import uuid


PKI = Path("/etc/platform-test-pki")
CONFIG = Path("/etc/platform-test-loki/config.alloy")
STATE = Path("/var/lib/platform-test-loki")
MAX_BODY = 2 * 1024 * 1024
MAX_DECODED = 4 * 1024 * 1024
WRITER_DN = (("commonName", "platform-loki-writer"),)
CASES = (
    "accepted", "untrusted-ca", "wrong-hostname", "mimir-identity",
    "probe-identity", "missing-client", "invalid-key", "mismatched-key", "redirect",
)
ERRORS = {
    "untrusted-ca": r"x509: certificate signed by unknown authority",
    "wrong-hostname": r"x509: certificate is valid for .*not wrong[.]example[.]invalid",
    "missing-client": r"(?i)(certificate required|bad certificate)",
    "invalid-key": r"(?i)(failed to find any PEM data|failed to parse.*private key)",
    "mismatched-key": r"(?i)private key does not match public key",
}
TLS_FAILURES = ("untrusted-ca", "wrong-hostname", "missing-client")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def protected(path, mode):
    """Check every parent with lstat; never accept a symlink or hardlinked file."""
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, f"unsafe fixture parent: {parent}")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == mode,
            f"unsafe fixture file: {path}")


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        require(pos < len(data), "truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise AssertionError("oversized varint")


def unsnappy(data):
    size, pos = varint(data, 0)
    require(0 < size <= MAX_DECODED, "unbounded decoded Loki body")
    output = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:
            length = tag >> 2
            if length >= 60:
                width = length - 59
                require(pos + width <= len(data), "truncated literal length")
                length = int.from_bytes(data[pos:pos + width], "little")
                pos += width
            length += 1
            require(pos + length <= len(data) and len(output) + length <= size,
                    "unbounded/truncated literal")
            output.extend(data[pos:pos + length])
            pos += length
        else:
            width = {1: 1, 2: 2, 3: 4}[kind]
            require(pos + width <= len(data), "truncated copy offset")
            offset = int.from_bytes(data[pos:pos + width], "little")
            pos += width
            length = (tag >> 2) + 1
            if kind == 1:
                offset |= (tag & 0xE0) << 3
                length = ((tag >> 2) & 7) + 4
            require(0 < offset <= len(output) and len(output) + length <= size,
                    "invalid Snappy copy")
            for _ in range(length):
                output.append(output[-offset])
    require(len(output) == size, "Snappy length mismatch")
    return bytes(output)


def fields(data):
    pos = 0
    while pos < len(data):
        tag, pos = varint(data, pos)
        number, wire = tag >> 3, tag & 7
        require(number > 0, "invalid protobuf field")
        if wire == 0:
            value, pos = varint(data, pos)
        else:
            if wire == 2:
                length, pos = varint(data, pos)
            else:
                require(wire in (1, 5), "unsupported protobuf wire type")
                length = {1: 8, 5: 4}[wire]
            require(pos + length <= len(data), "truncated protobuf field")
            value = data[pos:pos + length]
            pos += length
        yield number, wire, value


def payload_evidence(body):
    entries = 0
    markers = []
    for number, wire, stream in fields(unsnappy(body)):
        if (number, wire) != (1, 2):
            continue
        stream_fields = list(fields(stream))
        labels = [v.decode("utf-8") for n, w, v in stream_fields if (n, w) == (1, 2)]
        require(len(labels) == 1, "missing/duplicate stream labels")
        for n, w, entry in stream_fields:
            if (n, w) != (2, 2):
                continue
            lines = [v.decode("utf-8") for n, w, v in fields(entry) if (n, w) == (2, 2)]
            require(len(lines) == 1, "missing/duplicate entry line")
            entries += 1
            if re.fullmatch(r"platform-loki-fixture-[a-z-]+-[0-9a-f]{32}", lines[0]):
                require('job="systemd-journal"' in labels[0]
                        and 'environment="disposable-loki-test"' in labels[0],
                        "journal record lacks production source labels")
                markers.append(lines[0])
    require(entries > 0, "empty Loki push")
    return {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
            "entries": entries, "markers": markers}


def client_metrics(opener):
    # Alloy 1.18.1's sharded client logs retry errors at debug, not info. Its
    # native counters provide bounded in-flight failure evidence; shutdown below
    # also requires the final concrete TLS error, without altering the template.
    with opener.open("http://127.0.0.1:12346/metrics", timeout=1) as response:
        raw = response.read(MAX_BODY + 1)
    require(len(raw) <= MAX_BODY, "unbounded Alloy metrics response")
    values = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(
            r'(loki_write_(?:sent_entries_total|dropped_entries_total|batch_retries_total|'
            r'request_duration_seconds_count))\{([^}]+)\} ([0-9.eE+-]+)', line)
        if not match or 'host="127.0.0.1:18543"' not in match[2]:
            continue
        key = match[1]
        if key.endswith("_count"):
            status = re.search(r'status_code="(-?[0-9]+)"', match[2])
            if status is None:
                raise AssertionError("missing native request status label")
            key += "/" + status[1]
        values[key] = values.get(key, 0) + float(match[3])
    return values


class FixtureSocket(ssl.SSLSocket):
    fixture_sni: str | None


class Receiver(http.server.HTTPServer):
    def __init__(self, port, case, sink=False):
        super().__init__(("127.0.0.1", port), Handler)
        self.case = case
        self.sink = sink
        self.events = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.sslsocket_class = FixtureSocket
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(PKI / "server.crt", PKI / "server.key")
        self.context.load_verify_locations(PKI / "ca.crt")
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.set_servername_callback(self.sni)

    @staticmethod
    def sni(connection, name, _context):
        # Capture even a wrong name, allowing the *client* hostname verifier to
        # reject it. Valid HTTP pushes independently require the exact SNI.
        connection.fixture_sni = name

    def record(self, event):
        if len(self.events) >= 128:
            raise RuntimeError("fixture request bound exceeded")
        self.events.append(event)

    def get_request(self):
        connection, address = self.socket.accept()
        self.record({"event": "connect"})
        connection.settimeout(2)
        try:
            connection = cast(FixtureSocket, self.context.wrap_socket(connection, server_side=True))
        except (OSError, ssl.SSLError):
            self.record({"event": "tls-rejected"})
            connection.close()
            raise
        peer = connection.getpeercert() or {}
        self.record({"event": "tls", "peer_dn": peer.get("subject"),
                     "sni": connection.fixture_sni, "version": connection.version()})
        return connection, address

    def handle_error(self, request, client_address):
        # No request/body dump on errors. Any malformed request fails the case.
        self.record({"event": "handler-error"})


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        server = cast(Receiver, self.server)
        connection = cast(FixtureSocket, self.connection)
        lengths = self.headers.get_all("Content-Length", [])
        require(len(lengths) == 1 and re.fullmatch(r"[0-9]{1,8}", lengths[0])
                and not self.headers.get_all("Transfer-Encoding"), "invalid body framing")
        length = int(lengths[0])
        require(0 < length <= MAX_BODY, "unbounded Loki request body")
        body = self.rfile.read(length)
        require(len(body) == length, "truncated Loki body")
        require(self.headers.get("Content-Type") == "application/x-protobuf",
                "not a native Loki protobuf push")
        evidence = payload_evidence(body)
        peer = connection.getpeercert() or {}
        peer_dn = tuple(pair for rdn in peer.get("subject", ()) for pair in rdn)
        require(connection.version() in ("TLSv1.2", "TLSv1.3"), "obsolete negotiated TLS")
        host = self.headers.get("Host")
        sni = connection.fixture_sni
        status = 204
        if peer_dn != WRITER_DN:
            status = 401
        elif host != f"127.0.0.1:{server.server_port}" or sni != "monitoring.example.invalid":
            status = 421
        elif self.path != "/loki/api/v1/push":
            status = 404
        elif server.case == "redirect" and not server.sink:
            status = 307
        self.send_response(status)
        if status == 307:
            # Same host, different port: an unsafe redirect would reuse the TLS
            # client credential and preserve the POST body. Sink records even
            # handshakes, not just POSTs, to detect credential forwarding.
            self.send_header("Location", "https://127.0.0.1:18544/loki/api/v1/push")
        if status == 401:
            self.send_header("WWW-Authenticate", 'Mutual realm="loki-fixture"')
        reply = b"wrong writer identity\n" if status == 401 else b""
        self.send_header("Content-Length", str(len(reply)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)
        self.wfile.flush()
        self.close_connection = True
        server.record({"event": "response", "peer_dn": peer_dn, "sni": sni,
                       "host": host, "path": self.path, "method": self.command,
                       "status": status, "tls": connection.version(), **evidence})

    def log_message(self, format, *args):
        pass


def run_case(case, directory, origin, sink):
    marker = f"platform-loki-fixture-{case}-{uuid.uuid4().hex}"
    logfile = directory / "alloy.log"
    observed = None
    metrics = {}
    with logfile.open("xb") as log:
        os.chmod(logfile, 0o600)
        process = subprocess.Popen([
            "/usr/bin/alloy", "run", f"--storage.path={directory / 'data'}",
            "--server.http.listen-addr=127.0.0.1:12346", "--disable-reporting",
            str(CONFIG),
        ], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            ready = False
            while time.monotonic() < deadline:
                require(logfile.stat().st_size <= MAX_DECODED, "unbounded Alloy diagnostic log")
                text = logfile.read_text()
                if case in ("invalid-key", "mismatched-key"):
                    key_error = re.search(ERRORS[case], text)
                    if key_error:
                        require(not origin.events, "invalid key reached the network")
                        print(f"Native Alloy {case} error: {key_error[0]}")
                        return
                require(process.poll() is None, "Alloy exited before case evidence")
                if case in ("invalid-key", "mismatched-key"):
                    time.sleep(0.2)
                    continue
                try:
                    with opener.open("http://127.0.0.1:12346/-/ready", timeout=1) as response:
                        ready = response.status == 200
                except (OSError, urllib.error.URLError):
                    pass
                if ready:
                    break
                time.sleep(0.2)
            require(ready, "Alloy not ready; no sender evidence")
            # Native journal I/O; no hand-written source component or push client.
            subprocess.run(["systemd-cat", "--identifier=platform-loki-fixture"],
                           input=marker + "\n", text=True, check=True, timeout=3)
            subprocess.run(["journalctl", "--sync"], check=True, timeout=3,
                           stdout=subprocess.DEVNULL)
            journal = subprocess.check_output([
                "journalctl", "--directory=/var/log/journal", "--no-pager",
                "--output=cat", "--identifier=platform-loki-fixture", "--lines=10",
            ], text=True, timeout=3)
            require(marker in journal.splitlines(), "live marker missing from native journal")
            while time.monotonic() < deadline:
                require(process.poll() is None, "Alloy exited before delivery/rejection evidence")
                require(logfile.stat().st_size <= MAX_DECODED, "unbounded Alloy diagnostic log")
                text = logfile.read_text()
                responses = [e for e in origin.events if e["event"] == "response"]
                matched = [e for e in responses if marker in e["markers"]]
                require(not sink.events, "redirect target contacted: credential forwarding possible")
                require(not any(e["event"] == "handler-error" for e in origin.events),
                        "receiver could not validate native payload")
                require(len(origin.events) < 128, "fixture request bound exceeded")
                metrics = client_metrics(opener)
                sent = metrics.get("loki_write_sent_entries_total", 0)
                retries = metrics.get("loki_write_batch_retries_total", 0)
                if case == "accepted":
                    proven = any(e["status"] == 204 for e in matched) and sent > 0 and metrics.get(
                        "loki_write_request_duration_seconds_count/204", 0) > 0
                elif case in ("mimir-identity", "probe-identity", "redirect"):
                    status = 307 if case == "redirect" else 401
                    expected_dn = (("commonName", "platform-mimir-writer"),) if case == "mimir-identity" else (
                        (("commonName", "platform-external-probe-client"),) if case == "probe-identity" else WRITER_DN
                    )
                    require(all(e["status"] == status and e["peer_dn"] == expected_dn
                                for e in responses), "wrong HTTP rejection or peer identity")
                    # 401 and 307 are terminal Loki batch errors, not retryable
                    # 429/5xx responses. The same live marker must arrive once.
                    require(len(matched) <= 1, "Alloy retried a terminal HTTP response")
                    require(retries == 0, "Alloy retried a terminal HTTP status")
                    proven = bool(matched) and bool(re.search(
                        rf'final error sending batch.*status={status}\b', text)) and metrics.get(
                        f"loki_write_request_duration_seconds_count/{status}", 0) > 0 and metrics.get(
                        "loki_write_dropped_entries_total", 0) > 0
                else:
                    require(not responses, "TLS failure unexpectedly reached HTTP")
                    proven = retries > 0 and metrics.get(
                        "loki_write_request_duration_seconds_count/-1", 0) > 0 and any(
                        e["event"] == "tls-rejected" for e in origin.events)
                if case != "accepted":
                    require(sent == 0, "Alloy counted rejected entries as sent")
                    require(not any(e["status"] == 204 for e in responses),
                            "negative case accepted a payload")
                if proven:
                    observed = observed or time.monotonic()
                    # Allow retry/redirect regressions to become visible instead
                    # of ending at the first response/readiness observation.
                    if time.monotonic() - observed >= 3:
                        return
                else:
                    observed = None
                time.sleep(0.2)
            raise AssertionError(f"no native sender proof for {case}")
        except Exception:
            # Container cleanup removes the private diagnostics. Emit a bounded
            # tail on failure so the first coordinated run can be diagnosed;
            # this is Alloy's own disposable client log, not journal payloads.
            with logfile.open("rb") as diagnostics:
                diagnostics.seek(0, os.SEEK_END)
                diagnostics.seek(max(0, diagnostics.tell() - 8192))
                print(diagnostics.read(8192).decode("utf-8", errors="replace"), file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:
                # The native 1.18.1 queue drain bound is 15s. Let it emit the
                # concrete final TLS failure before killing a stuck process.
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                raise AssertionError("Alloy exceeded its bounded shutdown")
            print(json.dumps({"case": case, "native_client_metrics": metrics}, sort_keys=True))
            if case in TLS_FAILURES and observed is not None:
                match = re.search(ERRORS[case], logfile.read_text())
                if match is None:
                    raise AssertionError(f"missing concrete native TLS error for {case}")
                print(f"Native Alloy {case} error: {match[0]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    args = parser.parse_args()
    for name in ("ca.crt", "server.crt", "loki-writer.crt", "mimir-writer.crt",
                 "client.crt", "untrusted-ca.crt"):
        protected(PKI / name, 0o644)
    for name in ("ca.key", "server.key", "loki-writer.key", "mimir-writer.key",
                 "client.key", "untrusted-ca.key", "invalid.key"):
        protected(PKI / name, 0o600)
    protected(CONFIG, 0o644)
    config = CONFIG.read_text()
    require('prometheus.' not in config and 'loki.source.journal "system"' in config,
            "not the isolated role-rendered journal configuration")
    require(re.search(r"follow_redirects\s*=\s*false", config)
            and re.search(r"insecure_skip_verify\s*=\s*false", config)
            and re.search(r'min_version\s*=\s*"TLS12"', config),
            "role template lacks the strict Loki transport contract")
    directory = STATE / args.case
    directory.mkdir(mode=0o700)
    origin = Receiver(18543, args.case)
    sink = Receiver(18544, args.case, sink=True)
    threads = []
    for server in (origin, sink):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        run_case(args.case, directory, origin, sink)
        require(all(thread.is_alive() for thread in threads), "receiver thread exited")
    finally:
        for server in (origin, sink):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
        require(not any(thread.is_alive() for thread in threads), "receiver thread leaked")
        evidence = directory / "evidence.json"
        with evidence.open("x") as output:
            os.chmod(evidence, 0o600)
            json.dump({"origin": origin.events, "redirect_sink": sink.events}, output)
        # Preserve compact, non-secret payload/transport evidence in the harness
        # output too, since its final cleanup destroys the disposable container.
        print(json.dumps({
            "case": args.case,
            "origin_events": len(origin.events),
            "redirect_sink_events": len(sink.events),
            "journal_pushes": [e for e in origin.events
                               if e["event"] == "response" and e["markers"]],
        }, sort_keys=True))
    require(not sink.events, "redirect target contacted during sender shutdown")
    responses = [e for e in origin.events if e["event"] == "response"]
    if args.case == "accepted":
        require(all(e["status"] == 204 for e in responses), "positive case rejected on shutdown")
    elif args.case in ("mimir-identity", "probe-identity", "redirect"):
        status = 307 if args.case == "redirect" else 401
        require(all(e["status"] == status for e in responses), "wrong terminal status on shutdown")
        markers = [marker for e in responses for marker in e["markers"]]
        require(len(markers) == len(set(markers)), "terminal HTTP response retried on shutdown")
    else:
        require(not responses, "TLS/key failure reached HTTP on shutdown")
        if args.case in ("invalid-key", "mismatched-key"):
            require(not origin.events, "invalid key reached the network on shutdown")
    print(f"Native Alloy Loki {args.case}: passed (synthetic HTTP acceptance only)")


if __name__ == "__main__":
    main()
