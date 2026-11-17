# Sertifikat mTLS (server saja)

Hanya berisi cert untuk **server**:
- **CA**: `ca.pem`, `ca-key.pem` — dipakai server untuk verify client cert dan untuk API generate client cert
- **Server**: `server-cert.pem`, `server-key.pem` — dipakai TCP listener

Server baca dari sini bila `WAFIO_MTLS_CERTS_DIR` tidak diset. Bila file belum ada, server bisa generate CA dan server cert ke folder ini.

**Client cert** tidak disimpan di sini; didapat dari API (POST /api/projects/:id/mtls-keys), simpan sendiri untuk koneksi TCP.
