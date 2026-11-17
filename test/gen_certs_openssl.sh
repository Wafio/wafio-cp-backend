#!/usr/bin/env bash
# Generate cert server mTLS saja (CA + server). Client cert dari API: POST /api/projects/:id/mtls-keys
# Jalankan dari root project: ./test/gen_certs_openssl.sh
# Output di certs/: ca.pem, ca-key.pem, server-cert.pem, server-key.pem

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$ROOT/certs"
CONF="$SCRIPT_DIR/openssl.cnf"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "=== CA ==="
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 365 -key ca-key.pem -out ca.pem \
  -subj "/CN=wafio-ca" \
  -extensions v3_ca -config "$CONF"

echo "=== Server cert ==="
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 365 \
  -extensions v3_server -extfile "$CONF"
rm -f server.csr

rm -f ca.srl 2>/dev/null || true
echo "Done. Cert server di $CERT_DIR"
ls -la "$CERT_DIR"/*.pem
