#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ROCKY_IMAGE="${MONITORING_HAPROXY_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-monitoring-haproxy-capability-$$"
TEST_DIR=/etc/monitoring-haproxy-test
RENDER_PARENT="$ROOT_DIR/.ansible"
RENDER_DIR=""

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [[ "${MONITORING_HAPROXY_KEEP_CONTAINER:-0}" == 1 ]]; then
    printf 'Retained capability container: %s\n' "$CONTAINER" >&2
  else
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  if [[ -n "$RENDER_DIR" ]]; then
    rm -rf -- "$RENDER_DIR"
  fi
}
trap cleanup EXIT

if [[ -L "$RENDER_PARENT" ]]; then
  fail 'Monitoring HAProxy render parent must not be a symlink'
fi
mkdir -p "$RENDER_PARENT"
RENDER_DIR="$(mktemp -d "$RENDER_PARENT/monitoring-haproxy-render.XXXXXXXX")"
RENDER_NAME="$(basename "$RENDER_DIR")"
"$ROOT_DIR/scripts/in-container" ansible-playbook \
  tests/fixtures/monitoring-haproxy/render.yml \
  -e "monitoring_haproxy_test_output_dir=/workspace/.ansible/$RENDER_NAME" \
  >/dev/null

client_request() {
  local identity=$1
  local method=$2
  local connect_host=$3
  local request_host=$4
  local path=$5
  local -a method_args
  shift 5

  if [[ "$method" == HEAD ]]; then
    method_args=(--head)
  else
    method_args=(--request "$method")
  fi

  podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
    --max-time 3 \
    --http1.1 \
    --cacert "$TEST_DIR/server-ca.crt" \
    --cert "$TEST_DIR/${identity}.pem" \
    --resolve "${connect_host}:443:127.0.0.1" \
    "${method_args[@]}" \
    -H "Host: ${request_host}" \
    "$@" \
    "https://${connect_host}:443${path}"
}

client_status() {
  client_request "$@" --output /dev/null --write-out '%{http_code}'
}

postgres_round_trip() {
  podman exec "$CONTAINER" python3 -c \
    'import socket; s=socket.create_connection(("127.0.0.1",5432),2); s.sendall(b"pg-canary"); print(s.recv(64).decode("ascii")); s.close()'
}

assert_frontend_tls_rejected() {
  local identity=$1
  local host=${2:-loki.test.invalid}
  local http_code
  local status
  local -a certificate_args=()

  if [[ "$identity" != none ]]; then
    certificate_args=(--cert "$TEST_DIR/${identity}.pem")
  fi

  set +e
  http_code="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
    --max-time 3 --http1.1 \
    --cacert "$TEST_DIR/server-ca.crt" \
    "${certificate_args[@]}" \
    --resolve "${host}:443:127.0.0.1" \
    -H "Host: ${host}" \
    --output /dev/null --write-out '%{http_code}' \
    "https://${host}:443/" 2>/dev/null)"
  status=$?
  set -e

  [[ "$status" -ne 0 && "$http_code" == 000 ]] \
    || fail "Monitoring HAProxy did not reject ${identity} during the TLS handshake"
}

assert_frontend_alpn() {
  local offered=$1
  local expected=$2
  local output

  output="$(podman exec --interactive "$CONTAINER" openssl s_client \
    -connect 127.0.0.1:443 \
    -servername grafana.test.invalid \
    -cert "$TEST_DIR/grafana-browser.crt" \
    -key "$TEST_DIR/grafana-browser.key" \
    -CAfile "$TEST_DIR/server-ca.crt" \
    -alpn "$offered" </dev/null 2>&1)"
  grep -q "$expected" <<<"$output" \
    || fail "Monitoring HAProxy negotiated unexpected ALPN for ${offered}"
}

podman run \
  --detach \
  --name "$CONTAINER" \
  --workdir /workspace \
  --volume "${ROOT_DIR}:/workspace:ro,Z" \
  "$ROCKY_IMAGE" \
  sleep infinity >/dev/null

podman exec "$CONTAINER" dnf -qy install \
  curl haproxy openssl python3 >/dev/null
package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$package_identity" == haproxy-0:3.0.5-6.el10_2.1.x86_64 ]] \
  || fail "Monitoring HAProxy package identity mismatch: ${package_identity}"
build_features="$(podman exec "$CONTAINER" /usr/sbin/haproxy -vv)"
grep -q 'Built with OpenSSL version' <<<"$build_features" \
  || fail 'Monitoring HAProxy candidate lacks OpenSSL support'
grep -q 'Built with the Prometheus exporter as a service' <<<"$build_features" \
  || fail 'Monitoring HAProxy candidate lacks Prometheus exporter support'

podman exec "$CONTAINER" mkdir -p "$TEST_DIR"
podman exec "$CONTAINER" bash \
  /workspace/tests/fixtures/monitoring-haproxy/setup-pki.sh
podman exec "$CONTAINER" install -m 0640 \
  "/workspace/.ansible/$RENDER_NAME/roles.map" \
  "$TEST_DIR/rendered-roles.map"
podman exec "$CONTAINER" /usr/sbin/haproxy -c \
  -f "/workspace/.ansible/$RENDER_NAME/haproxy.cfg" \
  || fail 'HAProxy 3.0.5 rejected the rendered monitoring policy'
podman exec "$CONTAINER" install -m 0640 \
  "/workspace/.ansible/$RENDER_NAME/haproxy.cfg" \
  "$TEST_DIR/haproxy.cfg"

for fixture in loki mimir grafana s3 wrong untrusted patroni; do
  printf '%s\n' 200 | podman exec --interactive "$CONTAINER" \
    tee "/tmp/${fixture}.status" >/dev/null
done

podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.1 --port 19000 --plaintext \
  --expected-host s3.test.invalid --node s3 \
  --status-file /tmp/s3.status --sni-log /tmp/s3.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.1 --port 19001 --plaintext --allowed-path /health \
  --expected-host localhost --node s3-admin \
  --status-file /tmp/s3.status --sni-log /tmp/s3-admin.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.2 --port 18444 \
  --cert "$TEST_DIR/loki-backend.test.invalid.crt" \
  --key "$TEST_DIR/loki-backend.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --expected-host loki.test.invalid --node loki \
  --status-file /tmp/loki.status --sni-log /tmp/loki.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.3 --port 18443 \
  --cert "$TEST_DIR/grafana-backend.test.invalid.crt" \
  --key "$TEST_DIR/grafana-backend.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --expected-host grafana.test.invalid --node grafana \
  --status-file /tmp/grafana.status --sni-log /tmp/grafana.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.8 --port 18445 \
  --cert "$TEST_DIR/mimir-backend.test.invalid.crt" \
  --key "$TEST_DIR/mimir-backend.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --expected-host mimir.test.invalid \
  --expected-host alertmanager.test.invalid --node mimir \
  --status-file /tmp/mimir.status --sni-log /tmp/mimir.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.4 --port 18444 \
  --cert "$TEST_DIR/other-backend.test.invalid.crt" \
  --key "$TEST_DIR/other-backend.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --expected-host loki.test.invalid --node wrong \
  --status-file /tmp/wrong.status --sni-log /tmp/wrong.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.6 --port 18444 \
  --cert "$TEST_DIR/untrusted-backend.test.invalid.crt" \
  --key "$TEST_DIR/untrusted-backend.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --expected-host loki.test.invalid --node untrusted \
  --status-file /tmp/untrusted.status --sni-log /tmp/untrusted.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/https_fixture.py \
  --bind 127.0.0.5 --port 18448 \
  --cert "$TEST_DIR/patroni.test.invalid.crt" \
  --key "$TEST_DIR/patroni.test.invalid.key" \
  --client-ca "$TEST_DIR/client-ca/ca.crt" \
  --allowed-path /primary \
  --expected-host postgresql.test.invalid --node patroni \
  --status-file /tmp/patroni.status --sni-log /tmp/patroni.sni >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/monitoring-haproxy/tcp_fixture.py \
  --bind 127.0.0.5 --port 15433 >/dev/null

wrong_fixture_response=""
untrusted_fixture_response=""
for _ in {1..30}; do
  wrong_fixture_response="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
    --max-time 3 --cacert "$TEST_DIR/server-ca.crt" \
    --cert "$TEST_DIR/backend-client.pem" \
    --resolve other-backend.test.invalid:18444:127.0.0.4 \
    -H 'Host: loki.test.invalid' \
    https://other-backend.test.invalid:18444/ready 2>/dev/null || true)"
  untrusted_fixture_response="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
    --max-time 3 --cacert "$TEST_DIR/untrusted-ca.crt" \
    --cert "$TEST_DIR/backend-client.pem" \
    --resolve loki-3.test.invalid:18444:127.0.0.6 \
    -H 'Host: loki.test.invalid' \
    https://loki-3.test.invalid:18444/ready 2>/dev/null || true)"
  if grep -q '"node":"wrong"' <<<"$wrong_fixture_response" \
    && grep -q '"node":"untrusted"' <<<"$untrusted_fixture_response"; then
    break
  fi
  sleep 1
done
grep -q '"node":"wrong"' <<<"$wrong_fixture_response" \
  || fail 'Wrong-identity backend fixture was not healthy under its actual identity'
grep -q '"node":"untrusted"' <<<"$untrusted_fixture_response" \
  || fail 'Untrusted-CA backend fixture was not healthy under its own CA'

podman exec "$CONTAINER" /usr/sbin/haproxy -c -f "$TEST_DIR/haproxy.cfg" \
  || fail 'HAProxy 3.0.5 rejected the monitoring capability policy'
podman exec --detach "$CONTAINER" /usr/sbin/haproxy -db -f "$TEST_DIR/haproxy.cfg" \
  >/dev/null

writer_response=""
for _ in {1..30}; do
  writer_response="$(client_request alloy-writer POST \
    loki.test.invalid loki.test.invalid /loki/api/v1/push \
    -H 'X-Scope-OrgID: attacker-tenant' --data '{}' \
    --write-out $'\n%{http_code}' 2>/dev/null || true)"
  if grep -q '"node":"loki"' <<<"$writer_response"; then
    break
  fi
  sleep 1
done
if ! grep -q '"client_cn":"haproxy-backend"' <<<"$writer_response"; then
  printf 'Writer response: %s\n' "$writer_response" >&2
  fail 'Monitoring backend mTLS did not present the HAProxy client identity'
fi
grep -q '"tenant":"synthetic-tenant"' <<<"$writer_response" \
  || fail 'Monitoring HAProxy did not replace the client-supplied tenant'
grep -q '"method":"POST"' <<<"$writer_response" \
  || fail 'Monitoring HAProxy did not route the synthetic writer request'

query_response=""
for _ in {1..30}; do
  query_response="$(client_request grafana-loki-query GET \
    loki.test.invalid loki.test.invalid /loki/api/v1/query_range \
    --write-out $'\n%{http_code}' 2>/dev/null || true)"
  if grep -q '"node":"loki"' <<<"$query_response"; then
    break
  fi
  sleep 1
done
if ! grep -q '"node":"loki"' <<<"$query_response"; then
  printf 'Loki query response: %s\n' "$query_response" >&2
  fail 'Monitoring HAProxy rejected the mapped Loki query identity'
fi
alertmanager_response="$(client_request grafana-alertmanager GET \
  alertmanager.test.invalid alertmanager.test.invalid \
  /alertmanager/api/v2/alerts)"
grep -q '"node":"mimir"' <<<"$alertmanager_response" \
  || fail 'Monitoring HAProxy rejected the integrated Alertmanager route'
[[ "$(client_status alloy-writer GET loki.test.invalid \
  loki.test.invalid /loki/api/v1/query_range)" == 403 ]] \
  || fail 'Monitoring HAProxy allowed a writer to query Loki'
[[ "$(client_status grafana-loki-query POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy allowed a query identity to write Loki data'
[[ "$(client_status alloy-writer GET loki.test.invalid \
  loki.test.invalid /loki/api/v1/push)" == 403 ]] \
  || fail 'Monitoring HAProxy accepted the wrong method on the writer path'
[[ "$(client_status grafana-loki-query POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/query_range --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy accepted the wrong method on the query path'
[[ "$(client_status grafana-loki-query GET loki.test.invalid \
  loki.test.invalid /unapproved)" == 403 ]] \
  || fail 'Monitoring HAProxy accepted an unapproved path'
[[ "$(client_status alloy-writer POST loki.test.invalid \
  unknown.test.invalid /loki/api/v1/push --data '{}')" == 421 ]] \
  || fail 'Monitoring HAProxy accepted an unknown Host header'
[[ "$(client_status unmapped-client POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy accepted an unmapped client identity'
[[ "$(client_status alloy-writer-wrong-subject POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy authorized a matching CN with the wrong subject DN'
[[ "$(client_status grafana-browser POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy allowed the browser identity to write Loki data'
[[ "$(client_status alloy-writer GET grafana.test.invalid \
  grafana.test.invalid /login)" == 403 ]] \
  || fail 'Monitoring HAProxy allowed the writer identity to reach Grafana'

grafana_probe_response="$(client_request monitoring-probe GET \
  grafana.test.invalid grafana.test.invalid /api/health)"
grep -q '"node":"grafana"' <<<"$grafana_probe_response" \
  || fail 'Monitoring HAProxy rejected the Grafana probe route'
loki_probe_response="$(client_request monitoring-probe GET \
  loki.test.invalid loki.test.invalid /ready)"
grep -q '"node":"loki"' <<<"$loki_probe_response" \
  || fail 'Monitoring HAProxy rejected the Loki probe route'
mimir_probe_response="$(client_request monitoring-probe GET \
  mimir.test.invalid mimir.test.invalid /ready)"
grep -q '"node":"mimir"' <<<"$mimir_probe_response" \
  || fail 'Monitoring HAProxy rejected the Mimir probe route'
operator_response="$(client_request operator GET \
  mimir.test.invalid mimir.test.invalid /-/ready)"
grep -q '"node":"mimir"' <<<"$operator_response" \
  || fail 'Monitoring HAProxy rejected an approved operator route and source'
[[ "$(client_status operator GET loki.test.invalid \
  loki.test.invalid /-/ready)" == 403 ]] \
  || fail 'Monitoring HAProxy ignored operator route service qualification'
[[ "$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
  --max-time 3 --http1.1 --interface 127.0.0.2 \
  --cacert "$TEST_DIR/server-ca.crt" --cert "$TEST_DIR/operator.pem" \
  --resolve mimir.test.invalid:443:127.0.0.1 \
  -H 'Host: mimir.test.invalid' --output /dev/null --write-out '%{http_code}' \
  https://mimir.test.invalid/-/ready)" == 403 ]] \
  || fail 'Monitoring HAProxy accepted an operator outside its management source policy'
[[ "$(client_status monitoring-probe GET grafana.test.invalid \
  grafana.test.invalid /login)" == 403 ]] \
  || fail 'Monitoring probe identity reached an unapproved Grafana path'
[[ "$(client_status monitoring-probe GET loki.test.invalid \
  loki.test.invalid /loki/api/v1/query_range)" == 403 ]] \
  || fail 'Monitoring probe identity queried Loki'
[[ "$(client_status monitoring-probe POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring probe identity wrote Loki data'
[[ "$(client_status monitoring-probe POST mimir.test.invalid \
  mimir.test.invalid /ready --data '{}')" == 403 ]] \
  || fail 'Monitoring probe identity used an unapproved Mimir method'
[[ "$(client_status monitoring-probe GET mimir.test.invalid \
  mimir.test.invalid /prometheus/api/v1/query)" == 403 ]] \
  || fail 'Monitoring probe identity queried Mimir'
[[ "$(client_status monitoring-probe POST mimir.test.invalid \
  mimir.test.invalid /api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring probe identity wrote Mimir data'
[[ "$(client_status monitoring-probe GET s3.test.invalid \
  s3.test.invalid /health)" == 403 ]] \
  || fail 'Monitoring probe identity reached S3'
for method in DELETE GET PUT; do
  [[ "$(client_status monitoring-s3-probe "$method" s3.test.invalid \
    s3.test.invalid /observer-canary/canary)" == 200 ]] \
    || fail "Monitoring S3 probe rejected approved method ${method}"
done
for method in HEAD POST; do
  [[ "$(client_status monitoring-s3-probe "$method" s3.test.invalid \
    s3.test.invalid /observer-canary/canary)" == 403 ]] \
    || fail "Monitoring S3 probe accepted unapproved method ${method}"
done
[[ "$(client_status monitoring-s3-probe GET loki.test.invalid \
  loki.test.invalid /ready)" == 403 ]] \
  || fail 'Monitoring S3 probe identity reached Loki'
[[ "$(client_status monitoring-probe GET loki.test.invalid \
  loki.test.invalid /api/health)" == 403 ]] \
  || fail 'Monitoring probe used the Grafana health path on Loki'
[[ "$(client_status monitoring-probe GET mimir.test.invalid \
  mimir.test.invalid /api/health)" == 403 ]] \
  || fail 'Monitoring probe used the Grafana health path on Mimir'
[[ "$(client_status monitoring-probe GET grafana.test.invalid \
  grafana.test.invalid /ready)" == 403 ]] \
  || fail 'Monitoring probe used a readiness path on Grafana'
[[ "$(client_status monitoring-probe GET s3.test.invalid \
  s3.test.invalid /ready)" == 403 ]] \
  || fail 'Monitoring probe used a readiness path on S3'

assert_frontend_tls_rejected none s3.test.invalid
assert_frontend_tls_rejected revoked-client
assert_frontend_tls_rejected untrusted-client grafana.test.invalid
assert_frontend_tls_rejected untrusted-client s3.test.invalid
assert_frontend_alpn h2 'No ALPN negotiated'
assert_frontend_alpn h2,http/1.1 'ALPN protocol: http/1.1'

grafana_response="$(client_request grafana-browser GET \
  grafana.test.invalid grafana.test.invalid /login)"
grep -q '"node":"grafana"' <<<"$grafana_response" \
  || fail 'Monitoring HAProxy rejected the browser mTLS identity'
for method in GET HEAD POST PUT PATCH DELETE OPTIONS; do
  [[ "$(client_status grafana-browser "$method" grafana.test.invalid \
    grafana.test.invalid /api/dashboards/db)" == 200 ]] \
    || fail "Monitoring HAProxy rejected Grafana UI method ${method}"
done
[[ "$(client_status grafana-browser CONNECT grafana.test.invalid \
  grafana.test.invalid /api/dashboards/db)" =~ ^(400|403)$ ]] \
  || fail 'Monitoring HAProxy accepted CONNECT on the Grafana host'
[[ "$(client_status grafana-browser TRACE grafana.test.invalid \
  grafana.test.invalid /api/dashboards/db)" == 403 ]] \
  || fail 'Monitoring HAProxy accepted TRACE on the Grafana host'

assert_frontend_tls_rejected none
s3_response="$(client_request garage-s3 PUT \
  s3.test.invalid s3.test.invalid \
  '/loki-blocks/folder%2Fobject?partNumber=2&uploadId=abc&x=1&x=2' \
  --path-as-is \
  -H 'Authorization: AWS4-HMAC-SHA256 synthetic-signature' \
  -H 'X-Amz-Date: 20260802T170000Z' \
  -H 'X-Amz-Content-Sha256: 9f5cfe34bc7a2f9d68073a17c6b8a0f9a23adda568e702babdde40450313d2ae' \
  --data-binary 'synthetic-s3-payload')"
grep -q '"node":"s3"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy rejected the mapped S3 mTLS identity'
grep -q '"authorization":"AWS4-HMAC-SHA256 synthetic-signature"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the S3 Authorization header'
grep -q '"host":"s3.test.invalid"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the signed S3 Host header'
grep -q '"method":"PUT"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the signed S3 method'
grep -Fq '"path":"/loki-blocks/folder%2Fobject?partNumber=2&uploadId=abc&x=1&x=2"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the signed S3 path or query'
grep -q '"payload_sha256":"9f5cfe34bc7a2f9d68073a17c6b8a0f9a23adda568e702babdde40450313d2ae"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the signed S3 payload'
grep -q '"x_amz_content_sha256":"9f5cfe34bc7a2f9d68073a17c6b8a0f9a23adda568e702babdde40450313d2ae"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the S3 content hash header'
grep -q '"x_amz_date":"20260802T170000Z"' <<<"$s3_response" \
  || fail 'Monitoring HAProxy changed the S3 date header'
for method in GET HEAD POST PUT DELETE; do
  [[ "$(client_status garage-s3 "$method" s3.test.invalid \
    s3.test.invalid /method-check)" == 200 ]] \
    || fail "Monitoring HAProxy rejected S3 method ${method}"
done
[[ "$(client_status garage-s3 CONNECT s3.test.invalid \
  s3.test.invalid /loki-blocks/object)" =~ ^(400|403)$ ]] \
  || fail 'Monitoring HAProxy accepted CONNECT on the S3 host'
[[ "$(client_status alloy-writer GET s3.test.invalid \
  s3.test.invalid /loki-blocks/object)" == 403 ]] \
  || fail 'Monitoring HAProxy allowed a writer identity to reach S3'
[[ "$(client_status garage-s3 POST loki.test.invalid \
  loki.test.invalid /loki/api/v1/push --data '{}')" == 403 ]] \
  || fail 'Monitoring HAProxy allowed the S3 identity to reach Loki'

printf '%s\n' 503 | podman exec --interactive "$CONTAINER" \
  tee /tmp/loki.status >/dev/null
excluded_backend_response=""
for _ in {1..10}; do
  sleep 1
  excluded_backend_response="$(client_request grafana-loki-query GET \
    loki.test.invalid loki.test.invalid /loki/api/v1/query_range \
    --write-out $'\n%{http_code}' || true)"
  if [[ "${excluded_backend_response##*$'\n'}" == 503 ]]; then
    break
  fi
done
if [[ "${excluded_backend_response##*$'\n'}" != 503 ]]; then
  printf 'Invalid TLS backend exclusion response: %s\n' \
    "$excluded_backend_response" >&2
  fail 'Monitoring HAProxy did not exclude invalid TLS backend identities'
fi
if grep -Eq '"node":"(wrong|untrusted)"' <<<"$excluded_backend_response"; then
  fail 'Monitoring HAProxy forwarded to an invalid TLS backend identity'
fi

for fixture in loki mimir grafana wrong untrusted patroni; do
  for _ in {1..30}; do
    if podman exec "$CONTAINER" test -s "/tmp/${fixture}.sni"; then
      break
    fi
    sleep 1
  done
done
podman exec "$CONTAINER" grep -qx loki-backend.test.invalid /tmp/loki.sni \
  || fail 'Monitoring HAProxy omitted Loki backend SNI'
podman exec "$CONTAINER" grep -qx mimir-backend.test.invalid /tmp/mimir.sni \
  || fail 'Monitoring HAProxy omitted Mimir backend SNI'
podman exec "$CONTAINER" grep -qx grafana-backend.test.invalid /tmp/grafana.sni \
  || fail 'Monitoring HAProxy omitted Grafana backend SNI'
podman exec "$CONTAINER" grep -qx loki-2.test.invalid /tmp/wrong.sni \
  || fail 'Monitoring HAProxy omitted the configured wrong-identity test SNI'
podman exec "$CONTAINER" grep -qx loki-3.test.invalid /tmp/untrusted.sni \
  || fail 'Monitoring HAProxy omitted the configured untrusted-CA test SNI'
podman exec "$CONTAINER" grep -qx patroni.test.invalid /tmp/patroni.sni \
  || fail 'Monitoring HAProxy omitted Patroni check SNI'

postgres_response=""
for _ in {1..30}; do
  postgres_response="$(postgres_round_trip 2>/dev/null || true)"
  [[ "$postgres_response" == pg-canary ]] && break
  sleep 1
done
[[ "$postgres_response" == pg-canary ]] \
  || fail 'Monitoring HAProxy did not route raw PostgreSQL TCP to the Patroni primary'
printf '%s\n' 503 | podman exec --interactive "$CONTAINER" \
  tee /tmp/patroni.status >/dev/null
for _ in {1..10}; do
  sleep 1
  if [[ "$(postgres_round_trip 2>/dev/null || true)" != pg-canary ]]; then
    break
  fi
done
if [[ "$(postgres_round_trip 2>/dev/null || true)" == pg-canary ]]; then
  fail 'Monitoring HAProxy routed PostgreSQL TCP after Patroni rejected primary status'
fi

metrics="$(podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  http://127.0.0.1:18404/metrics)"
grep -q '^haproxy_' <<<"$metrics" \
  || fail 'Monitoring HAProxy metrics endpoint returned no metrics'
[[ "$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
  --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18404/)" == 404 ]] \
  || fail 'Monitoring HAProxy metrics listener exposed another path'
[[ "$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
  --interface 127.0.0.2 --output /dev/null --write-out '%{http_code}' \
  http://127.0.0.1:18404/metrics)" == 403 ]] \
  || fail 'Monitoring HAProxy metrics listener accepted a denied source'

podman exec "$CONTAINER" cp "$TEST_DIR/haproxy.cfg" /tmp/rejected.cfg
printf '%s\n' 'this is not valid HAProxy syntax' \
  | podman exec --interactive "$CONTAINER" tee -a /tmp/rejected.cfg >/dev/null
if podman exec "$CONTAINER" /usr/sbin/haproxy -c -f /tmp/rejected.cfg \
  >/dev/null 2>&1; then
  fail 'HAProxy accepted an invalid monitoring policy candidate'
fi

printf 'Monitoring HAProxy 3.0 capability check passed\n'
