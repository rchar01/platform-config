#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def aws_quote(value: str, *, keep_slash: bool = False) -> str:
    safe = "-_.~/" if keep_slash else "-_.~"
    return urllib.parse.quote(value, safe=safe)


def sign(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send one AWS SigV4 S3 request")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--method", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", default="")
    parser.add_argument("--query", action="append", default=[])
    parser.add_argument("--range")
    parser.add_argument("--body-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-status", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    if not access_key or not secret_key:
        raise SystemExit("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")

    endpoint = urllib.parse.urlsplit(args.endpoint)
    if endpoint.scheme != "http" or not endpoint.netloc or endpoint.path not in {"", "/"}:
        raise SystemExit("endpoint must be an HTTP origin without a path")

    method = args.method.upper()
    payload = args.body_file.read_bytes() if args.body_file else b""
    payload_hash = hashlib.sha256(payload).hexdigest()
    object_path = f"/{args.bucket}"
    if args.key:
        object_path += f"/{args.key}"
    canonical_uri = aws_quote(object_path, keep_slash=True)

    query_pairs: list[tuple[str, str]] = []
    for item in args.query:
        name, separator, value = item.partition("=")
        if not separator:
            raise SystemExit(f"query must use name=value form: {item}")
        query_pairs.append((aws_quote(name), aws_quote(value)))
    canonical_query = "&".join(
        f"{name}={value}" for name, value in sorted(query_pairs)
    )

    now = datetime.datetime.now(datetime.UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    headers = {
        "host": endpoint.netloc,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if args.range:
        headers["range"] = args.range
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(
        f"{name}:{' '.join(headers[name].split())}\n" for name in sorted(headers)
    )
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    scope = f"{date_stamp}/{args.region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    date_key = sign(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    region_key = sign(date_key, args.region)
    service_key = sign(region_key, "s3")
    signing_key = sign(service_key, "aws4_request")
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    url = urllib.parse.urlunsplit(
        (endpoint.scheme, endpoint.netloc, canonical_uri, canonical_query, "")
    )
    request_headers = {
        "Authorization": authorization,
        "Host": endpoint.netloc,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Date": amz_date,
    }
    if args.range:
        request_headers["Range"] = args.range
    request = urllib.request.Request(
        url,
        data=payload if method in {"POST", "PUT"} else None,
        headers=request_headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = response.status
            response_body = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        response_body = error.read()
    except urllib.error.URLError as error:
        raise SystemExit(f"S3 request failed before receiving HTTP status: {error}") from error
    except TimeoutError as error:
        raise SystemExit("S3 request timed out before receiving HTTP status") from error

    args.output.write_bytes(response_body)
    if status != args.expect_status:
        diagnostic = response_body[:2048].decode("utf-8", errors="replace")
        print(
            f"expected HTTP {args.expect_status}, received {status}: {diagnostic}",
            file=sys.stderr,
        )
        return 1
    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
