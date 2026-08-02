#!/usr/bin/env bash
set -euo pipefail

PKI_DIR=/etc/monitoring-haproxy-test
CLIENT_CA_DIR=$PKI_DIR/client-ca

mkdir -p "$CLIENT_CA_DIR/newcerts"
install -m 0600 \
  /workspace/tests/fixtures/monitoring-haproxy/openssl-client-ca.cnf \
  "$CLIENT_CA_DIR/openssl.cnf"
: >"$CLIENT_CA_DIR/index.txt"
printf '%s\n' 1000 >"$CLIENT_CA_DIR/serial"
printf '%s\n' 1000 >"$CLIENT_CA_DIR/crlnumber"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=monitoring-client-test-ca \
  -keyout "$CLIENT_CA_DIR/ca.key" \
  -out "$CLIENT_CA_DIR/ca.crt" >/dev/null 2>&1

issue_client() {
  local name=$1

  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=${name}" \
    -keyout "$PKI_DIR/${name}.key" \
    -out "$PKI_DIR/${name}.csr" >/dev/null 2>&1
  openssl ca -batch -config "$CLIENT_CA_DIR/openssl.cnf" \
    -in "$PKI_DIR/${name}.csr" \
    -out "$PKI_DIR/${name}.crt" >/dev/null 2>&1
  cat "$PKI_DIR/${name}.key" "$PKI_DIR/${name}.crt" \
    >"$PKI_DIR/${name}.pem"
}

for identity in \
  alloy-writer \
  grafana-loki-query \
  grafana-browser \
  unmapped-client \
  revoked-client \
  haproxy-backend; do
  issue_client "$identity"
done

openssl ca -batch -config "$CLIENT_CA_DIR/openssl.cnf" \
  -revoke "$PKI_DIR/revoked-client.crt" >/dev/null 2>&1
openssl ca -batch -config "$CLIENT_CA_DIR/openssl.cnf" \
  -gencrl -out "$CLIENT_CA_DIR/ca.crl" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=monitoring-server-test-ca \
  -keyout "$PKI_DIR/server-ca.key" \
  -out "$PKI_DIR/server-ca.crt" >/dev/null 2>&1

issue_server() {
  local name=$1
  local sans=$2

  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=${name}" \
    -addext "subjectAltName=${sans}" \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$PKI_DIR/${name}.key" \
    -out "$PKI_DIR/${name}.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 \
    -in "$PKI_DIR/${name}.csr" \
    -CA "$PKI_DIR/server-ca.crt" \
    -CAkey "$PKI_DIR/server-ca.key" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$PKI_DIR/${name}.crt" >/dev/null 2>&1
}

issue_server frontend.test.invalid \
  'DNS:loki.test.invalid,DNS:grafana.test.invalid,DNS:bad-backend.test.invalid,DNS:untrusted-backend.test.invalid'
issue_server loki-backend.test.invalid 'DNS:loki-backend.test.invalid'
issue_server grafana-backend.test.invalid 'DNS:grafana-backend.test.invalid'
issue_server other-backend.test.invalid 'DNS:other-backend.test.invalid'
issue_server patroni.test.invalid 'DNS:patroni.test.invalid'

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=monitoring-untrusted-test-ca \
  -keyout "$PKI_DIR/untrusted-ca.key" \
  -out "$PKI_DIR/untrusted-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj /CN=untrusted-backend.test.invalid \
  -addext 'subjectAltName=DNS:untrusted-backend.test.invalid' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$PKI_DIR/untrusted-backend.test.invalid.key" \
  -out "$PKI_DIR/untrusted-backend.test.invalid.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "$PKI_DIR/untrusted-backend.test.invalid.csr" \
  -CA "$PKI_DIR/untrusted-ca.crt" \
  -CAkey "$PKI_DIR/untrusted-ca.key" \
  -CAcreateserial \
  -copy_extensions copy \
  -out "$PKI_DIR/untrusted-backend.test.invalid.crt" >/dev/null 2>&1

cat \
  "$PKI_DIR/frontend.test.invalid.key" \
  "$PKI_DIR/frontend.test.invalid.crt" \
  >"$PKI_DIR/frontend.pem"
cp "$PKI_DIR/haproxy-backend.pem" "$PKI_DIR/backend-client.pem"
chmod 0600 "$PKI_DIR"/*.key "$PKI_DIR"/*.pem "$CLIENT_CA_DIR/ca.key"
chmod 0644 "$PKI_DIR"/*.crt "$CLIENT_CA_DIR/ca.crt" "$CLIENT_CA_DIR/ca.crl"
