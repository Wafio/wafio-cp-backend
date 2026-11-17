# Kontrak CLI — biner WAFio

Control plane (`wafio`) dan dua agent (`wafio-waf-agent`, `wafio-host-agent`). Diekstrak dari definisi `cobra.Command` di `cmd/wafio/` dan pembacaan variabel lingkungan di `cmd/wafio-*-agent/`. `wafio-host-agent` dibangun di repositori `wafio-agent-host`; bagiannya tetap di sini karena installer dan control plane memakai kontrak lingkungannya. API portal ada di repositori `wafio-portal` (`docs/portal-api.md`).

Konvensi keluaran biner: keluar dengan kode 0 saat berhasil, bukan-0 saat gagal. Kegagalan konfigurasi memakai `log.Fatalf`, yang keluar dengan kode 1.

## command: wafio serve

Menjalankan control plane: HTTP pada port 9087, gRPC mTLS pada port 9090.

| Flag | Tipe | Rules |
|---|---|---|
| `--migrate` | bool | Default false. Bila true, migrasi dijalankan sebelum server start |
| `--migrations` | string | Default `migrations`. Path direktori migrasi; wajib ada bila `--migrate` diberikan |

Konfigurasi dimuat dengan urutan `config/config.yaml`, lalu variabel lingkungan `WAFIO_*`, lalu flag CLI. Setiap kunci YAML memetakan ke satu variabel lingkungan: `server.http_addr` menjadi `WAFIO_SERVER_HTTP_ADDR`.

Sebelum server start, `Config.Validate` (`internal/config/validate.go`) memeriksa konfigurasi dan menghentikan boot dengan daftar semua kesalahan bila ada yang gagal. Yang diperiksa antara lain: `jwt.secret` kosong, masih placeholder bawaan atau contoh, atau kurang dari 32 karakter; `jwt.expire_hours` tidak positif; `totp.enc_key` kosong atau tidak 32 byte; `server.cors_allow_origins` berisi `*` bersama kredensial; `server.http_addr` kosong; trusted proxy tidak valid; `log.level` di luar debug, info, warn, error; `database.name` atau `database.host` kosong, `database.port` di luar 1-65535; batas penerimaan data agent di luar rentang.

Security: authn=tidak-berlaku-proses-lokal; privilege=tidak-butuh-root; secrets=dibaca-dari-config-atau-env-tidak-pernah-dari-argv; audit=log-startup; catatan=jwt.secret-placeholder-ditolak-saat-boot

## command: wafio migrate

Subperintah: `up`, `down`, `down --steps N`, dan `fresh`. Versi yang sedang berlaku ada di `SELECT version, dirty FROM schema_migrations`.

| Flag | Tipe | Rules |
|---|---|---|
| `--migrations` | string | Default kosong, artinya deteksi otomatis dari akar proyek |
| `--steps` | int | Hanya untuk `down`. Jumlah migrasi yang dibatalkan |

`fresh` membuang seluruh objek lalu menerapkan ulang semuanya. Perintah ini menghancurkan data dan hanya untuk pengembangan.

Security: authn=akses-shell-ke-host; authz=kredensial-basis-data-dari-config; destruktif=fresh-menghapus-seluruh-data-hanya-untuk-pengembangan; audit=riwayat-versi-golang-migrate

## command: wafio fetch-data

Mengunduh data keamanan: basis data GeoIP, daftar reputasi IP, sidik jari JA3, dan daftar User-Agent.

| Flag | Tipe | Rules |
|---|---|---|
| `--dir` | string | Default `security-data`. Direktori tujuan |
| `--maxmind-key` | string | Kunci lisensi MaxMind GeoLite2. Menimpa nilai config |
| `--force` | bool | Default false. Unduh ulang meski berkas sudah ada |
| `--only` | string | Daftar dipisah koma dari `geoip`, `geoip-country`, `geoip-city`, `geoip-asn`, `firehol`, `ja3`, `ua` |
| `--profile` | string | Default `all`. Salah satu dari `all`, `control-plane`, `agent` |

Security: authn=tidak-berlaku; egress=mengunduh-dari-sumber-hulu-pihak-ketiga; integritas=tidak-ada-verifikasi-tanda-tangan-pada-artefak-terunduh; secrets=kunci-maxmind-lewat-flag-terlihat-di-daftar-proses

Catatan: memberikan kunci lisensi lewat `--maxmind-key` membuatnya terlihat di `ps`. Lebih aman menyetel `WAFIO_MAXMIND_LICENSE_KEY`.

Catatan: daftar reputasi IP diunduh langsung dari penyedianya untuk melindungi server ini dan tidak boleh dijual kembali. Sumber, kredit, dan lisensinya ada di `NOTICES.txt`.

## command: wafio-waf-agent

Sidecar WAF L7. Dikonfigurasi seluruhnya lewat variabel lingkungan; tidak ada flag.

| Env key | Rules |
|---|---|
| `WAFIO_GRPC_SERVER` | Wajib. Alamat control plane dalam bentuk host:port |
| `WAFIO_GRPC_CLIENT_CERT`, `WAFIO_GRPC_CLIENT_KEY`, `WAFIO_GRPC_CA_CERT` | Wajib. Path berkas kredensial mTLS |
| `WAFIO_GRPC_SERVER_NAME` | Opsional. Menimpa SNI ketika sertifikat server tidak cocok dengan alamat sambungan |
| `WAFIO_AGENT_NAME` | Wajib sudah terdaftar untuk agent WAF; dipakai sebagai kunci pencarian pada `Hello` |
| `WAFIO_HOST_KEY` | Opsional. Mengikat agent ke satu baris pada tabel `hosts` |
| `WAFIO_SERVER_URL` | Basis URL HTTP untuk endpoint ingest |
| `WAFIO_SECURITY_DATA_DIR` | Opsional. Direktori data keamanan itu sendiri (berisi `geoip/`, `ja4/`, `user-agents/`); tanpa nilai ini `/etc/wafio/security-data`. Flag padanannya `--security-data-dir`. File env v1 menulis `WAFIO_CRS_DEFAULT_DIR` (`<dir>/crs`, `<dir>/crs/coreruleset` atau `<dir>/crs/coreruleset/rules`); agent masih menurunkan direktori dari nama itu dan mencatat satu peringatan, dan installer menggantinya dengan variabel ini |
| `WAFIO_GEO_COUNTRY_DB_PATH`, `WAFIO_GEO_CITY_DB_PATH`, `WAFIO_GEO_ASN_DB_PATH` | Path basis data MaxMind |
| `WAFIO_UA_BAD_BOT_FILE` | Daftar User-Agent untuk bot protection |
| `WAFIO_AGENT_API_KEY` | Warisan. Digantikan `WAFIO_HOST_KEY` |
| `WAFIO_BODY_DECODE_BUDGET_BYTES` | Opsional. Budget memori se-proses untuk dekode body `Content-Encoding` (byte atau KiB/MiB/GiB/K/M/G; default 64 MiB; `0` = nonaktif; nilai tidak valid → default + log). Dibaca saat dekode pertama. Reservasi per dekode mencakup buffer keluaran dan state decoder (brotli ≈ 4–5 MiB untuk body kecil); budget di bawah state decoder → coding itu tidak didekode (`decompress_limit`). Melebihi budget → byte mentah diperiksa, `BodyScanSkipped=decompress_budget`, request ditandai sebagian tidak diperiksa, `content_scan.on_incomplete` berlaku bila content scan aktif dengan `block` diturunkan ke LOG (dipicu beban, bukan isi request) |
| `WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS` | Opsional. Jumlah jaringan berbeda (IPv4 /16, IPv6 /48, alamat klien yang sudah di-resolve) yang boleh memakai satu cookie challenge `_wafio_ch`; lebih dari itu cookie dicabut sampai kedaluwarsa dan pengunjung di-challenge ulang (default 8; `0` = nonaktif; nilai tidak valid → default + log) |
| `WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN` | Opsional. Batas `POST /_wafio/challenge/verify` per IP klien (alamat klien yang sudah di-resolve; IPv6 dihitung per /64) dalam jendela tetap 60 detik; yang melebihi dijawab 429 dengan `Retry-After: 60` sebelum pekerjaan verifikasi apa pun. Endpoint itu dilayani sebelum WAF dan limiter L7 flood, jadi batas ini yang menjaga cache token terpakai (default 120; `0` = nonaktif; nilai tidak valid → default + log; tabel 50.000 alamat). Banyak pengunjung di balik satu NAT berbagi hitungan yang sama: naikkan nilainya bila kantor besar di balik satu IP ditolak |
| `STATE_DIRECTORY` / `--state-dir` / `WAFIO_STATE_DIR` | Direktori state (dibuat 0700): `last-bundle.json` (cache bundle) dan `challenge-secret` (64 hex, 0600; kunci tanda tangan challenge saat `secret_key` kosong, dipakai bersama proses penerus tableflip; tanpa direktori state kunci acak per proses) |
| `NOTIFY_SOCKET` | Disetel systemd. Mengaktifkan `Type=notify`; `READY=1` dikirim hanya setelah bundle pertama diterima |

Mendukung upgrade tanpa downtime lewat `SIGUSR2` atau `systemctl reload`, memakai `cloudflare/tableflip`: proses baru mewarisi listener, proses lama menuntaskan koneksi lalu keluar.

Tidak ada API lokal (`/internal/config`, `/v1/analyze`): agent ini hanya membuka listener proxy per-app dari bundle dan, bila `WAFIO_METRICS_ADDR` diset, `/metrics` di alamat loopback. API lokal dengan token per-start hanya ada pada `wafio-host-agent`.

Security: authn=mTLS-untuk-gRPC-dan-host-key-untuk-HTTP-ingest; privilege=tidak-butuh-root; secrets=path-berkas-lewat-env-bukan-nilai-inline; reload=SIGUSR2-zero-downtime; audit=WAFDecisionEvent-per-request

## command: wafio-host-agent

Firewall kernel dan tracing runtime. **Hanya Linux.** Memerlukan root dan `CAP_BPF`.

| Env key | Rules |
|---|---|
| `WAFIO_GRPC_SERVER` dan kredensial mTLS | Sama dengan agent WAF |
| `WAFIO_HOST_KEY` | Mengikat agent ke baris `hosts` |
| path objek eBPF | Objek CO-RE pra-bangun; tidak pernah diambil dari control plane |
| `WAFIO_PROTECTED_PROCESSES` | Opsional; flag `--protected-processes`. Daftar nama basename executable dipisah koma, **ditambahkan** ke daftar bawaan (`sshd`, `systemd`, `systemd-journald`, `containerd`, `dockerd`, `kubelet`). Tanpa `/`, `\`, `.`/`..`, karakter kontrol; item kosong ditolak |
| `WAFIO_PROTECTED_EXE_PATHS` | Opsional; flag `--protected-exe-paths`. Path executable persis dipisah koma: absolut, kanonik (`filepath.Clean`), tanpa segmen `..`, bukan direktori. Shell/interpreter/biner multi-call (`bash`, `sh`, `busybox`, `env`, `python*`, `perl*`, `node`, ...) di salah satu daftar diterima tetapi dicatat `WARNING` saat start dan `warning=risky_protected:<daftar>` di baris self-check |
| `WAFIO_PROTECTED_REPLACE_DEFAULTS` | Opsional; flag `--protected-replace-defaults`. Boolean; `true` mengganti (bukan menambah) daftar bawaan dan wajib disertai minimal satu entri |
| `WAFIO_LOCAL_API_TOKEN_FILE` | Opsional; flag `--local-api-token-file`. Default `/run/wafio/host-agent.token`. Token API lokal (`127.0.0.1:18089`) per-start, wajib sebagai Bearer pada setiap route kecuali `/healthz`. Berkas ditulis setiap kali listener lokal berjalan, juga bila eBPF atau tracing gagal start |
| `WAFIO_GEO_COUNTRY_DB_PATH` | Opsional. Cadangan untuk `--geoip-db` (lalu `WAFIO_GEOIP_DB_PATH`, nama lama); kosong keduanya = enricher GeoIP mati. Agent tidak lagi membaca `config.yaml` |
| `WAFIO_LOCAL_API_TOKEN_GROUP` | Opsional; flag `--local-api-token-group`. Grup pembaca berkas token (0640), mis. `wafio` untuk push IP-jail dari `wafio-waf-agent` |

Agent host tidak menjalankan pipeline WAF: `/v1/analyze`, `/v1/analyze-nginx`, `/internal/config` dan `/internal/telemetry` tidak dilayani lagi (404, juga dengan token). Flag `--jail-threshold`, `--jail-window-sec`, `--jail-duration-sec`, `--project-id`, `--connect-timeout-ms` dan `--rw-timeout-ms` diterima dan diabaikan (tersembunyi, deprecated) selama satu rilis. `--listen ""` mematikan API lokal; agent tetap berjalan dan mencatat hal itu.

`wafio-host-agent fetch-data` hanya mengunduh `geoip-country` (profil `host-agent`, DB-IP atau MaxMind lewat `--maxmind-key`); profil lain dan komponen lain ditolak. Set data WAF diunduh `wafio-waf-agent fetch-data`.

Objek eBPF wajib sudah ada di disk sebelum start. Kernel minimum 5.10 dengan BTF aktif untuk firewall eBPF (5.8/5.9 tidak didukung sejak 2026-10-10; objek XDP ditolak kernel itu).

Flag menang atas env. Entri tidak valid menghentikan start (`invalid protected-process configuration`). Saat tracing aktif, agent mencatat sekali daftar efektif (`protected-process set: names=[…] exe_paths=[…] builtin_defaults=merged|replaced`) dan satu baris cek mandiri (`protected-process self-check: kernel_set=present|absent map=trace_protected_tgids … protected_tgids=N matched_processes=M`) untuk verifikasi deploy.

Security: authn=mTLS; privilege=butuh-root-dan-CAP_BPF; kode=objek-eBPF-hanya-dari-disk-lokal-tidak-pernah-dari-jaringan; failmode=stub-non-Linux-mengembalikan-ErrNotSupported

## Aturan build

Semua biner masuk ke `build/`. Tidak pernah ke akar repositori atau ke `bin/`.

| Target | Perintah |
|---|---|
| Biner control plane untuk rilis, di `dist/controlplane/` (bundel dirakit dan ditandatangani oleh `scripts/release.sh` di wafio-release) | `./scripts/build-dist.sh <versi>` |
| Untuk pengembangan dan CI | `go build -trimpath -o build/ ./cmd/wafio` |

Objek eBPF dan agent host dibangun di repositori `wafio-agent-host`; agent WAF dibangun di `wafio-agent-waf`.

Build rilis adalah `go build -trimpath` biasa, tanpa obfuskasi: kode sumbernya terbuka. `CGO_ENABLED=0` diperlukan untuk biner Linux statis.
