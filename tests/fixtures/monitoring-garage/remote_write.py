#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import urllib.error
import urllib.request


def varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, wire_type: int, value: bytes) -> bytes:
    tag = varint((number << 3) | wire_type)
    return tag + (varint(len(value)) + value if wire_type == 2 else value)


def label(name: str, value: str) -> bytes:
    message = field(1, 2, name.encode()) + field(2, 2, value.encode())
    return field(1, 2, message)


def snappy_literal(payload: bytes) -> bytes:
    length = len(payload)
    if length < 60:
        tag = bytes([(length - 1) << 2])
    else:
        encoded_length = (length - 1).to_bytes(4, "little").rstrip(b"\x00")
        tag = bytes([(59 + len(encoded_length)) << 2]) + encoded_length
    return varint(length) + tag + payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Send one Prometheus remote-write sample")
    parser.add_argument("--url", required=True)
    parser.add_argument("--metric", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--timestamp-ms", required=True, type=int)
    parser.add_argument("--value", required=True, type=float)
    args = parser.parse_args()

    sample = field(1, 1, struct.pack("<d", args.value)) + field(
        2, 0, varint(args.timestamp_ms)
    )
    series = (
        label("__name__", args.metric)
        + label("case", args.case)
        + field(2, 2, sample)
    )
    payload = snappy_literal(field(1, 2, series))
    request = urllib.request.Request(
        args.url,
        data=payload,
        method="POST",
        headers={
            "Content-Encoding": "snappy",
            "Content-Type": "application/x-protobuf",
            "X-Prometheus-Remote-Write-Version": "0.1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        raise SystemExit(
            f"remote write returned HTTP {error.code}: {error.read().decode(errors='replace')}"
        ) from error
    if status not in {200, 204}:
        raise SystemExit(f"remote write returned HTTP {status}: {body.decode(errors='replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
