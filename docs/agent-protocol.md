# Kontrak gRPC — Agent Control

Sumber: `shared/proto/agent/v1/agent_control.proto`. Kode hasil generasi ada di `shared/agentpb/` dan tidak boleh diedit tangan.

Satu service, dua RPC, dua jenis agent. Autentikasi seluruhnya di lapisan TLS.

## Model autentikasi

Setiap tabel di bawah mengasumsikan hal ini dan tidak mengulanginya:

- TLS dengan `tls.RequireAndVerifyClientCert` terhadap CA milik control plane.
- SHA-256 dari sertifikat klien dicari di `mtls_credentials` untuk memetakan koneksi ke tepat satu `project_id`.
- Tidak ada lapisan autentikasi kedua. `agent_name` dan `host_key` di dalam `Hello` adalah kunci pencarian, bukan kredensial.
- Koneksi tanpa sertifikat klien yang valid diputus saat handshake, sebelum satu pun pesan aplikasi terbaca.

## rpc: Stream

Satu stream dua arah per proses agent. Pesan pertama dari klien wajib `Hello`.

| Param | Tipe | Rules |
|---|---|---|
| sertifikat klien | X.509 | Wajib. Rantai diverifikasi terhadap CA. Fingerprint SHA-256 wajib ada di `mtls_credentials`, jika tidak stream ditolak (`Unauthenticated`). Kredensial dicek ulang saat stream dibuka dan setiap 5 menit; revoke kredensial (`DELETE .../agent-grpc-credentials/{credId}`) langsung mengakhiri setiap stream yang memakainya dengan `Unauthenticated`; hapus project (dan hapus user pemilik project) mengakhiri stream semua kredensial project itu. Kredensial dibaca ulang juga setelah validasi `Hello`, sebelum `Welcome` dan bundle pertama, jadi revoke di tengah `Hello` tidak menerima apa pun. Download `DownloadMalwareDatabase` dilacak sama seperti `Stream` dan berhenti pada chunk berikutnya setelah revoke atau hapus project. Server mengirim GOAWAY setelah umur koneksi 24 jam (+5 menit grace); agent tersambung ulang dan diautentikasi ulang |
| pesan pertama | `AgentMessage` | Wajib berisi varian oneof `hello`. Pesan pertama jenis lain mengakhiri stream |
| kompresi | — | Stream tidak dikompresi di tingkat transport (grpc-go mendekompresi sebelum handler, sehingga alokasinya tidak bisa dibebankan). Agent host v1.9.0+ mengompresi batch telemetry sendiri (`CommandAck.payload`, lihat event CommandAck) setelah control plane mengumumkan `telemetry_gzip` |
| anggaran terima | — | v1.9.0+. Setiap pesan dibebankan sebesar ukurannya ke akun pemilik project, dan payload gzip sebesar ukuran aslinya (≤ 64 × panjangnya) sebelum didekompresi: 64 MiB/detik per akun, burst satu detiknya; akun yang aktif dalam 2 detik terakhir berbagi total seluruh proses 128 MiB/detik secara max-min adil (keduanya dapat diatur). Selama berutang, stream akun itu tidak membaca pesan berikutnya (flow control memperlambat agent-nya) dan bertanya lagi paling lambat tiap 1 detik; `last_seen` agent-nya tetap disegarkan 30 detik setelah heartbeat terakhir; tidak ada yang ditolak. Hello wajib ≤ 64 KiB (`InvalidArgument`); paling banyak 16 stream per koneksi |
| `hello.agent_name` | string | Agent yang sudah terdaftar di project tersambung ulang dengan barisnya (agent yang sudah dihapus — soft delete — tidak dikenali lagi). Nama yang belum dikenal didaftarkan otomatis untuk kedua jenis — skrip instalasi agent WAF hanya menetapkan nama dan tidak memanggil API register — paling banyak 20.000 agent hidup per project; di atasnya `ResourceExhausted` |
| `hello.agent_version` | string | Bebas; dipakai untuk pelaporan versi fleet |
| `hello.hostname` | string | Bebas; dipakai untuk tampilan |
| `hello.bundle_generation` | int64 | Hanya agent WAF. Informasional: server selalu mengirim bundel awal saat terhubung |
| `hello.host_key` | string | Opsional. Bila tidak kosong, diverifikasi terhadap tabel `hosts` — juga untuk agent yang sudah terdaftar (dulu diabaikan untuk agent host yang sudah dikenal) — dan harus milik project tersebut serta tidak dicabut, jika tidak `PermissionDenied` "invalid host_key"; pemeriksaan yang tidak bisa dijalankan (galat database, tidak ada slot verifikasi argon2id sebelum tenggat Hello 3 detik) → `Unavailable`, agent mengulang. Kunci yang sudah pernah terverifikasi terhadap hash tersimpan yang sama tidak menjalankan argon2id lagi. Kunci dicari lewat lookup id (128 bit SHA-256 seluruh kunci, migrasi 000105); kunci yang tersimpan sebelum 000105 dicari lewat prefix tampilan dan setiap kandidat diverifikasi, jadi dua host yang berbagi prefix 20 bit tidak lagi saling menolak. Kunci yang valid mengikat agent ke host itu |
| host dicabut | — | Agent yang terikat ke host yang dicabut — atau, tanpa host, yang `hello.hostname`-nya nama (atau hostname terlapor) host yang dicabut dan bukan milik host hidup mana pun — ditolak `PermissionDenied` "host revoked". Stream yang belum terikat host saat Hello (agent WAF yang ditautkan lewat hostname di latar belakang) mencari host agentnya lagi pada cek ulang periodik. Cabut atau hapus host (`POST …/hosts/{hostId}/revoke`, `DELETE …/hosts/{hostId}`) langsung menutup stream agent host itu dengan kode yang sama; host dibaca ulang juga setelah validasi `Hello` (sebelum `Welcome`) dan bersama cek ulang kredensial tiap 5 menit. Kredensial mTLS seluruh project tidak ikut dicabut; kredensial yang di-enroll dengan host key host itu ikut dihapus (lihat bagian "Kredensial terikat host") |
| `hello.agent_kind` | string | Petunjuk `waf`, `host`, atau `ebpf`. Diabaikan bila agent sudah terdaftar |
| `hello.features` (field 8) | repeated string | Opsional. Kemampuan binary agent; nama yang tidak dikenal diabaikan. Agent WAF mengirim satu nama: `script_rules` (`engine.FeatureScriptRules`) bila sidecar skrip tersedia, `no_script_rules` (`engine.FeatureNoScriptRules`) bila tidak; script rule lalu membuat setiap request app itu tidak selesai diperiksa, yaitu LOG. Control plane menyimpannya sebagai `agents.script_rules` (migrasi 000116; `false` untuk `no_script_rules`, `true` bila agent mengirim `script_rules` atau nama lain, null bila tidak ada feature atau agent host), menolak 400 `SCRIPT_RULES_UNSUPPORTED` pada pembuatan atau pengaktifan script rule untuk app yang semua agent-nya melaporkan `script_rules: false` (script rule yang sudah aktif tetap bisa diedit dan dimatikan), dan menampilkannya sebagai `script_rules` di objek agent API (daftar agent WAF fleet, agent per app); nilainya ditulis ulang pada setiap koneksi. Bundel tidak bergantung pada feature: setiap agent menerima bundel yang sama, hasil `engine.NormalizeBundle` (kunci dokumen v1 ditulis ulang: `inspection_off` menggantikan `disable_semantic` dan `disable_rule_based`, `skip_coraza_when_clean` dibuang, tuning rule dengan engine `crs` dibuang, `scan_mode` `crs_only` dan `semantic_only` menjadi `default`, `skip_crs` dibuang). Konfigurasi yang tersimpan tidak diubah, dan server mencatat tiap penulisan ulang sekali per app dan per koneksi. Nama yang dikirim agent v1 (`semantic_only`, `semantic_keys_jwt_graphql`, `field_rules_v2`, `custom_rule_field_paths`) diabaikan. Agent v1 yang lebih lama dari v1.9 tidak mengenal kunci `jwt` dan `graphql` di `semantic_override` dan `skip_semantic`, jadi menolak bundel yang memuatnya dan tetap melayani bundel yang di-cache. Agent host (v1.9.0+) mengirim `telemetry_demand`: ia menangani `BundleUpdate` `telemetry:demand` (lihat event BundleUpdate). Agent host dengan filter penerusan trace mengirim `trace_forward_filter` (`domain.TraceForwardFilterFeature`): ia menangani `BundleUpdate` `trace:forward_filter` |
| field 5 | — | `reserved`. Nomor field tidak boleh dipakai ulang setelah `waf_key` dibuang di migrasi 000017 |

### Kredensial terikat host (enrollment host key, migrasi 000108)

Kredensial yang dibuat di halaman Credentials berlaku untuk seluruh project (`mtls_credentials.host_id` NULL) dan memakai aturan `Hello` di atas tanpa perubahan. Kredensial hasil `POST /api/internal/host-enroll` diterbitkan untuk satu agent (jenis + nama) pada satu host; interseptor autentikasi menaruh pengikatnya (host, jenis, nama) di konteks stream dan `validateHello` menjalankan `validateBoundHello`. Server ini memegang kredensial itu persis pada identitasnya:

| Aturan | Efek |
|---|---|
| `hello.agent_name` | Harus sama dengan nama yang di-enroll; kosong dianggap `<hostname>@ebpf` (turunan yang sama dengan jalur project). Lain → `PermissionDenied` |
| `hello.agent_kind` | Petunjuk `waf` berarti WAF; selain itu (kosong, `host`, `ebpf`) berarti host. Harus sama dengan jenis yang di-enroll, jika tidak `PermissionDenied` |
| host | Harus ada di project dan belum dicabut. Galat pembacaan → `Unavailable` (gagal-tertutup; jalur project menerima saat galat). Cabut atau hapus host sudah menghapus kredensialnya, jadi ini lapis kedua |
| `hello.host_key` | Bila dikirim harus terverifikasi dan milik host yang terikat, jika tidak `PermissionDenied` |
| baris agent | Baris dengan nama + jenis itu pada host yang terikat, atau baris baru di host itu bila project belum punya agent bernama itu. Baris lain bernama sama (host lain, tanpa host, atau jenis lain) → `PermissionDenied`; baris yang belum menempel ke host TIDAK lagi diadopsi |
| audit penolakan | Hello yang ditolak dicatat `agent.rejected` (metadata `reason` = `agent_name` \| `agent_kind` \| `host_revoked` \| `host_key_invalid` \| `host_key_other_host` \| `agent_name_conflict`, `credential_id`, `host_id`, `agent_kind`, `agent_name`, `presented_name`, `presented_kind`, `presented_hostname`, IP peer), paling banyak sekali per kredensial dan alasan tiap 10 menit |

Akibatnya mesin dengan kredensial ter-enroll tidak dapat tersambung ulang dengan nama lain, jenis lain, atau untuk host lain, apa pun hostname yang dilaporkannya. Residu: kredensial seluruh project tetap dapat melakukannya (cabut di halaman Credentials).

Security: authn=mTLS-client-cert; authz=fingerprint-to-project-mapping; tenancy=project_id-dari-fingerprint; transport=TLS-wajib; replay=tidak-berlaku-stream-panjang; audit=agent_audit

Koneksi:

- Keepalive server: ping setelah 60 detik tanpa aktivitas, koneksi ditutup bila tidak dijawab dalam 20 detik. Enforcement policy: klien boleh ping paling sering tiap 15 detik (juga tanpa stream aktif); lebih sering dari itu koneksi ditutup (`too_many_pings`).
- Keepalive klien (agent WAF dan host): ping tiap 30 detik selama stream aktif, timeout 10 detik.
- `Welcome.agent_id` adalah `agents.id`, id yang ditampilkan dashboard dan API, bukan id kredensial mTLS. Kosong bila baris agent WAF belum terdaftar saat `Hello`.
- Reconnect agent: backoff eksponensial 1 → 30 detik dengan jitter ±20%, supaya restart control plane tidak membuat semua agent tersambung ulang di detik yang sama.
- Shutdown control plane: `GracefulStop` paling lama 10 detik, lalu `Stop()` memutus stream yang tersisa; agent tersambung ulang seperti biasa.

## event: Heartbeat

Agent ke server. Dikirim kedua jenis agent pada interval yang dinegosiasikan lewat `Welcome.heartbeat_seconds`.

| Field | Tipe | Rules |
|---|---|---|
| `unix_time` | int64 | Detik sejak epoch pada agent. Perbedaan dengan waktu server terlihat pada dashboard |
| `decisions_total` | uint64 | Penghitung monoton sejak agent start |
| `blocks_total` | uint64 | Penghitung monoton; wajib tidak melebihi `decisions_total` |
| `host_info_json` | bytes | Snapshot HostInfo ber-encoding JSON. Dikirim pada heartbeat pertama setelah connect dan setiap 5 menit. Kosong bila tidak berubah. Agent host menyertakan `ssh_ports` (port TCP listener sshd/dropbear yang terdeteksi); guard lockout firewall control plane mewajibkan salah satunya tetap terbuka (tanpa `ssh_ports` = 22 diasumsikan, dengan peringatan `SSH_PORT_ASSUMED`) |
| `analyze_panics_total` | optional uint64 | Hanya agent WAF (v1.2+). Panic yang ditangkap `Analyze`; request di-allow tanpa inspeksi penuh |
| `engine_panics_total` | optional uint64 | Hanya agent WAF (v1.2+). Panic engine semantik yang ditangkap di dalam scan (`engine.EnginePanicCount`) |
| `partial_coverage_total` | optional uint64 | Hanya agent WAF (v1.2+). Request yang cakupan scan semantiknya tidak lengkap, sehingga request ditandai sebagian tidak diperiksa (`application.PartialCoverageRequests`) |
| `parse_budget_exhausted_total` | optional uint64 | Hanya agent WAF (v1.2+). Scan yang melewatkan varian relaxed-parse karena anggaran kerja habis (`engine.ParseBudgetExhaustedCount`) |
| `bundle_source` (field 9) | optional string | Hanya agent WAF (v1.3+). Asal konfigurasi yang berlaku: `live` (dari stream ini), `cache` (`last-bundle.json` dimuat saat start), `cache_stale` (cache lebih tua dari `--bundle-cache-max-age`, default 7 hari; tetap diterapkan). Tidak diisi = belum ada bundle |
| `bundle_generation` (field 10) | optional int64 | Hanya agent WAF (v1.3+). Generasi bundle yang berlaku; diisi bersama `bundle_source` |
| `script_incomplete_total` (field 11) | optional uint64 | Hanya agent WAF (v1.4+). Evaluasi script rule yang tidak selesai (timeout, batas sandbox, panic, runtime error, anggaran request habis); verdict paling buruk LOG (`engine.ScriptIncompleteCount`) |
| `script_errors_total` (field 12) | optional uint64 | Hanya agent WAF (v1.4+). Bagian runtime error dari field 11 (`engine.ScriptErrorCount`) |
| `script_rules_rejected_total` (field 13) | optional uint64 | Hanya agent WAF (v1.4+). Script rule yang dibuang saat bundle dimuat karena memakai builtin di luar allowlist |
| `script_runs_in_flight` (field 14) | optional int64 | Hanya agent WAF (v1.4+). Gauge: run script yang goroutine-nya belum selesai. Server menyimpan nilai negatif sebagai 0 |
| `agent_panics_total` (field 15) | optional uint64 | Hanya agent WAF (v1.4+). Panic lain yang ditangkap agent (relay WebSocket, enforcement IP-jail); panic analyze/engine ada di field 5–6 |
| `analyze_latency_p50_us` (field 16) | optional uint64 | Hanya agent WAF (v1.4+). p50 latensi `Analyze` 5 menit terakhir, mikrodetik, diestimasi dari histogram (bucket 0,25/0,5/1/2/5/10/25/50/100/250/1000 ms; nilai di bucket overflow = 1 s). Tidak diisi bila `analyze_latency_samples` = 0 |
| `analyze_latency_p95_us` (field 17) | optional uint64 | Hanya agent WAF (v1.4+). p95, aturan sama dengan field 16 |
| `analyze_latency_p99_us` (field 18) | optional uint64 | Hanya agent WAF (v1.4+). p99, aturan sama dengan field 16; target inline < 5 ms |
| `analyze_latency_samples` (field 19) | optional uint64 | Hanya agent WAF (v1.4+). Jumlah analisis dalam jendela 5 menit (0 = tidak ada trafik) |
| `regex_rules_dropped_total` (field 20) | optional uint64 | Hanya agent WAF. Aturan kustom GUI/tuning yang dibuang saat bundle dimuat karena regex tidak valid atau programnya > 256 instruksi, kumulatif sejak agent start. Disimpan di `agents.waf_regex_rules_dropped_total` (migrasi 000097); daftar aturan menandai tiap aturan itu lewat `regex_error` |

Penghitung kesehatan inspeksi (field 5–8, 11–13, 15, 20) bersifat kumulatif sejak proses agent start dan kembali ke nol saat restart; field 14 adalah gauge dan field 16–19 meringkas jendela geser 5 menit. Field `optional` memberi presence eksplisit: agent lama (atau agent host/eBPF) tidak mengisinya, dan server membiarkan nilai tersimpan apa adanya (NULL = "belum dilaporkan", bukan nol). Server menyimpan nilai terakhir di kolom `agents` (field 5–8: migrasi 000086; field 11–19: migrasi 000096; field 20: migrasi 000097) dan mengembalikannya di `GET /api/fleet/agents`. Upgrade control plane lebih dulu; agent lama cukup tidak mengisi field baru.

`bundle_source`/`bundle_generation` (field 9–10) disimpan di `agents.waf_bundle_source` / `agents.waf_bundle_generation` (migrasi 000099) dalam `UPDATE` yang sama dan dikembalikan di `GET /api/fleet/agents` sebagai `bundle_source` / `bundle_generation`. Server hanya menerima `live`, `cache`, `cache_stale` dan `""` untuk `bundle_source`; nilai lain disimpan sebagai `unknown`. Generasi negatif disimpan 0. Perubahan sumber tetap dicatat di log per stream.

Security: authn=mTLS-client-cert; authz=project-dari-fingerprint; ratelimit=interval-ditetapkan-server-lewat-Welcome; audit=last_seen-diperbarui

## event: WAFDecisionEvent

Agent WAF ke server. Satu event per request HTTP yang dianalisis inline proxy. Agent eBPF tidak pernah mengirimnya.

| Field | Tipe | Rules |
|---|---|---|
| `ts_unix` | int64 | Waktu keputusan pada agent |
| `method`, `host`, `uri` | string | Konteks request seperti diterima |
| `remote_ip` | string | Diselesaikan `resolveRemoteIP`; menghormati sakelar percaya-proxy pada agent |
| `status` | int32 | Kode status HTTP yang diterima klien: respons blokir atau challenge, respons upstream, 502 untuk galat upstream. 0 = tidak tercatat (agent lama, atau event tanpa status seperti log handshake WebSocket). Disimpan di `waf_decisions.status` (migrasi 000117; NULL untuk 0) dan dijawab API sebagai `status`, 0 bila NULL |
| `score` | int32 | Skor keputusan. Ambang blokir default 150, ambang log default 80 |
| `action` | string | Wajib salah satu dari `allow`, `block`, `monitor` |
| `categories` | repeated string | Kategori serangan dari peta rule |
| `match_detail` | string | Cuplikan yang memicu deteksi |
| `analyze_method` | string | Lapisan mana yang memutuskan; menjadi `waf_decisions.analyze_method`. `rule_based` dan `hybrid` dari agent v1 disimpan sebagai `semantic`; baris lama tidak ditulis ulang, tetapi API menampilkan dan menghitungnya sebagai `semantic` |
| `app_id` | string | Boleh kosong untuk trafik host-header yang tak terpetakan |
| `user_agent`, `content_type` | string | Konteks request |
| `body_size` | int32 | Ukuran body sebelum pemotongan |
| `body_preview` | string | Bagian awal body (512 karakter); nilai field form/JSON/multipart bernama rahasia menjadi `[redacted]` seperti `request_body` |
| `cwe` | string | Dari peta taksonomi. **Kosong untuk 5 dari 13 engine semantic** |
| `latency_us` | int32 | Latensi keputusan dalam mikrodetik |
| `match_source` | string | Contoh `header:User-Agent`, `body`, `query:id`, `body:password`, `body.json:password`, `path` |
| `request_headers` | map string ke string | Disensor sebelum dikirim: `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` dibuang, nilai header bernama rahasia (`X-Api-Key`, `X-CSRF-Token`, `X-Amz-Security-Token` …) menjadi `[redacted]`; header yang disebut `match_source` eksak (`match_source_exact`) tetap — tereduksi untuk vonis JWT/Anomaly, Authorization: skema + segmen header JWT, Cookie: cookie yang disebut saja; sumber tebakan tidak mengecualikan nilai rahasia. Control plane menyensor lagi saat ingest untuk agent lama |
| `request_body` | string | 4096 byte pertama; kosong bila biner. Nilai field form, kunci JSON (semua kedalaman) dan field teks multipart bernama rahasia menjadi `[redacted]` kecuali field yang disebut `match_source` eksak |
| `query_params` | string | Query string; nilai parameter bernama rahasia (`api_key`, `token`, `access_token`, `password` …) menjadi `[redacted]` kecuali parameter yang disebut `match_source` eksak. Query string di `uri` disensor sama |
| `payload_type` | string | Contoh `json`, `xml`, `form-urlencoded` |
| `coverage` | string | v1.2+. Flag celah cakupan scan semantik, dipisah koma (contoh `field_cap,body_binary`); sama dengan penanda `coverage:<flags>` di `match_detail`, tetapi diisi juga untuk `allow`. Kosong = cakupan lengkap atau agent lama. Disimpan di `waf_decisions.coverage`. Flag `engine_disabled:<kunci>` menandai engine yang dimatikan operator untuk request itu (semua dua puluh kunci): informasi, bukan celah, jadi tidak menaikkan vonis dan tidak ada di penanda `coverage:` pada `match_detail`. Flag `engine_log_only:<kunci>` menandai engine yang `action`-nya `log` dan yang deteksi blokirnya ditahan menjadi LOG pada request itu (request diteruskan, kategori, skor dan detail sama dengan blokirnya); sama seperti flag sebelumnya ia informasi, bukan celah. API memecah teks ini: `coverage` berisi flag celah saja, `engines_off` berisi kunci engine yang dimatikan dan `engines_log_only` kunci engine yang ditahan, untuk baris baru dan lama |
| `match_source_exact` | bool | v1.9+ (field 25). `true` bila engine sendiri menyebut masukan `match_source` (semantik, content scan); `false` untuk sumber tebakan (URI utuh), sumber tanpa masukan, dan agent lama. Hanya sumber eksak yang menyimpan nilai bernama rahasia; control plane menyensor ulang saat ingest dengan nilai ini. Tidak disimpan |

Sampling dilakukan di sisi agent agar stream tidak dibanjiri.

Security: authn=mTLS-client-cert; authz=project-dari-fingerprint; pii=header-sensitif-disaring-sebelum-kirim; retensi=30-hari-hypertable; audit=waf_decisions-append-only

## event: CommandAck

Dipakai kedua agent untuk dua tujuan berbeda. Ini adalah kompromi yang disengaja dan terdokumentasi di proto.

| Field | Tipe | Rules |
|---|---|---|
| `command_id` | string | Agent WAF: cocok dengan `command_id` dari `KeyRotation`. Agent eBPF: harfiah `ebpf:telemetry` |
| `ok` | bool | Agent WAF: true bila rotasi berhasil. Agent eBPF: selalu true untuk telemetri |
| `error` | string | Agent WAF: pesan galat sungguhan. **Agent eBPF: payload JSON `PushPayload`, bukan galat.** Field ini dipakai ulang agar skema proto tidak perlu diubah |
| `payload` (field 4) | bytes | v1.9.0+, hanya agent host dengan `command_id="ebpf:telemetry:v2"`: gzip dari JSON `PushPayload` (sebagai pengganti `error`), dikirim hanya di stream yang control plane-nya mengumumkan `telemetry_gzip` (`telemetry:demand`). Control plane membaca ukuran asli dari trailer gzip (ISIZE, ≤ 8 MiB dan ≤ 64 × panjang member, `telemetrygz.MaxRatio`), membebankannya ke anggaran terima akun sebelum mendekompresi, dan menuntut ukuran serta CRC yang cocok; payload rusak, di atas rasio itu atau di stream tanpa pengumuman dibuang tanpa ingest (yang di atas rasio dan tanpa pengumuman juga tanpa beban), stream tetap berjalan. Agent mem-pad member yang akan terkompresi lebih dari 64× dengan blok deflate stored kosong (5 byte masing-masing, tanpa output) sampai panjangnya 1/64 batch (`telemetrygz.Encode`), jadi batch yang sah tidak pernah ditolak karena rasionya; pembaca gzip mana pun membacanya sebagai batch yang sama |

Batch telemetri v2 (`ebpf:telemetry:v2`, berisi `batch_id`) dideduplikasi per (project, agent, `batch_id`) dan dijawab `BundleUpdate{command_id="ebpf:telemetry:receipt"}`. Tanda terima batch yang diterima disimpan 2 menit dalam pool bersama 131.072 entri (progres retry per section 65.536 entri) yang dibagi adil per project: saat penuh, project yang memegang entri terbanyak melepas entri lamanya. Banjir batch kecil dengan `batch_id` baru dari satu project hanya memperpendek jendela deduplikasi project itu sendiri — resend batch-nya yang terlambat bisa tersimpan dua kali — dan tidak lagi membuat batch project lain ditolak (`process_accepted: false`, "receipt capacity exhausted"). Antrean penulis keputusan WAF (8.192 baris) dan antrean block window (1.024) juga dibagi adil per project dan dilayani round-robin.

Security: authn=mTLS-client-cert; authz=project-dari-fingerprint; integritas=payload-hanya-diterima-dalam-stream-terautentikasi; audit=telemetri-masuk-hypertable

## event: BundleUpdate

Server ke agent. Membawa konfigurasi, tidak pernah kode.

| Field | Tipe | Rules |
|---|---|---|
| isi bundle | JSON | Agent WAF: dokumen aturan WAF. Agent eBPF: state desired dan trace policy |
| guard lockout firewall | — | Agent eBPF menjalankan guard yang sama dengan control plane dan API lokal (`ebpf.ValidateHostFirewall`) sebelum mengubah map apa pun. State yang ditolak di-ack dengan `error` berawalan `apply refused (<CODE>): …`; control plane menampilkannya sebagai `bundle_status.status = "refused"` dengan `code`, dan kebijakan terakhir yang berhasil tetap berlaku. Agent menyimpan kebijakan terakhir yang berhasil beserta generasi dan endpoint control plane yang ter-pin (`/var/lib/wafio-host-agent/firewall-last-good.json`, cadangan `/run/wafio/…`, yang lebih baru menang; override `WAFIO_FIREWALL_STATE_FILE`) dan menerapkannya lagi saat start sebelum stream tersambung: control plane di-resolve dulu (atau endpoint tersimpan di-seed); bila keduanya tidak ada, egress Deny All tersimpan diterapkan dengan DNS diizinkan sampai endpoint ter-pin. Setelah Hello agent mengirim `CommandAck{command_id="ebpf:policy_source"}` (JSON `{"source":"saved|default|live","generation":…,"dns_relaxed":true?}` di `error`) → `bundle_status.source` / `saved_generation` / `dns_relaxed` (egress Deny All tersimpan berjalan dengan DNS diizinkan karena endpoint control plane belum ter-pin). Server selalu mengirim desired state, juga yang kosong: bagian yang tidak tersimpan dikirim eksplisit (daftar kosong, port policy mati, config default agent), sehingga state kosong = reset. Objek eBPF tanpa pengecualian untuk map `wafio_cp_endpoints` menolak egress Deny All dan entri blocklist `0.0.0.0/0`/`::/0`. Apply tidak mengosongkan conntrack |
| endpoint control plane | — | Sebelum setiap dial, agent host me-resolve `--grpc-server`, menulis alamat:port ke `wafio_cp_endpoints`, lalu men-dial persis endpoint itu (target `passthrough:///`, tanpa resolver DNS gRPC). Resolusi gagal = endpoint sebelumnya tetap dipakai |
| generasi | int64 | Monoton naik. Agent menyimpannya dan mengirim balik lewat `Hello.bundle_generation`. Agent WAF: generasi berasal dari satu sequence untuk semua agent (migrasi 000102), sehingga agent yang terdaftar ulang tidak pernah menerima generasi lebih rendah; bundel WAF membawa `agent_id` dan agent menolak generasi lebih rendah hanya untuk `agent_id` yang sama (bundel `agent_id` lain memulai urutan baru). Bundel konfigurasi WAF yang gagal diterapkan (observer belum siap, port sementara terpakai) dicoba ulang oleh agent dengan backoff 2 s–60 s, paling banyak 10 kali, dan di-ack ulang `ok` dengan `command_id` yang sama begitu berhasil; bundel lebih baru atau stream putus membatalkannya. Agent host: generasi lebih rendah ditolak; generasi sama dengan isi lain diterapkan (isi terbaru di stream berurutan adalah pandangan control plane) |
| target | — | Bundle WAF hanya dikirim ke agent WAF project tersebut; agent host/eBPF tidak pernah menerimanya |
| `command_id="telemetry:demand"` | JSON `{"live_for_sec":N,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":M}` | Hanya ke agent host yang melaporkan `hello.features` `telemetry_demand`. Bukan konfigurasi: agent tidak meng-ack, tidak menyimpan generasi. `telemetry_gzip: true` membuat agent mengirim batch telemetry sebagai `CommandAck.payload` gzip di stream itu. Saat tersambung N = sisa jendela live viewer agent itu (0 bila tidak ada; snapshot koneksi dan bandwidth tiap 60 detik); `N = 120` saat halaman Firewall membaca snapshot, dicocokkan per project dan agent, paling banyak sekali per 30 detik per agent (snapshot tiap 3 detik selama jendela; agent membatasi ≤ 600). Status on demand: `status_on_demand: true` (selalu dari control plane ini) membuat agent mengirim payload lambat (host info, status, trace stats, hit count rule) tiap 3 detik dan metrics tiap 1 detik hanya selama jendela status M detik atau jendela snapshot N detik, selain itu keduanya tiap 30 detik; payload lambat juga langsung saat tersambung, saat jendela terbuka dan setelah bundle konfigurasi diterapkan. Saat tersambung M = sisa jendela status (≥ sisa jendela snapshot, 0 bila tidak ada); `M = 120` saat dashboard membaca status (`/host/stream` channel `status`/`metrics`/`stats`/`hostinfo`, `GET …/host/status`, `…/host/metrics`, `…/host/trace/status`, `…/host/trace/stats`), paling banyak sekali per 30 detik per agent; permintaan snapshot membawa `N = M = 120`. Pesan tanpa `status_on_demand` (control plane lama): tiap 3 detik / 1 detik seperti sebelumnya. Agent tanpa fitur itu tidak pernah menerimanya |
| `command_id="trace:forward_filter"` | JSON `{"revision":R,"digest":"<32 hex>","filter":{"rules":[…],"correlation_stages":[…]}}` (≤ 1 MiB), atau penanda `{"revision":R,"digest":"<32 hex>","disabled":"too_large"}` bila filter > 1 MiB | Hanya ke stream agent host (kind `host`/`ebpf`) yang melaporkan `hello.features` `trace_forward_filter`: rule deteksi dan tahap korelasi yang dievaluasi ingest untuk host itu. Bukan konfigurasi: agent tidak meng-ack, tidak menyimpan generasi, tidak menyimpannya ke disk; filter berlaku hanya untuk stream itu. Setiap batch telemetry gRPC agent membawa `trace_forward` `{"digest":"…","rule_hits":{"<rule id>":n}}` — digest filter yang dipegang stream (kosong = belum ada) dan hit rule dari event yang tidak dikirim; control plane mengirim filter lagi bila digest berbeda (segera bila isinya berubah, selain itu paling sering tiap 10 detik), dan langsung ke stream yang tersambung setelah setiap penulisan rule deteksi host itu atau rantai korelasi project-nya. Penanda `too_large`: agent tidak memfilter dan melaporkan digest penanda (status `too_large`), sehingga tidak dikirim ulang. Filter dengan `revision` lain, digest yang tidak cocok dengan isinya, atau JSON rusak tidak diterapkan (agent mengirim semua event) |
| batas waktu kirim | — | Server mengirim di luar lock registrasi, paralel per stream, dengan batas waktu (default 10 detik). Stream yang `Send`-nya macet melewati batas diputus (`UNAVAILABLE`); agent menyambung ulang |
| cache agent | — | Agent WAF menulis setiap bundle yang berhasil diterapkan ke `$STATE_DIRECTORY/last-bundle.json` (atau `--state-dir` / `WAFIO_STATE_DIR`; temp + fsync + rename, mode 0600) dan menerapkannya saat start sebelum connect. File rusak diabaikan |
| kode yang dapat dieksekusi | — | Dilarang. Objek eBPF terkompilasi tidak pernah melintasi jalur ini |

Security: authn=mTLS-client-cert-arah-server; authz=hanya-bundle-milik-project-terikat-fingerprint; integritas=TLS; kode=tidak-pernah-dikirim; audit=perubahan-konfigurasi-tercatat-di-agent_audit

## event: KeyRotation

Server ke agent WAF saja. Agent eBPF mengabaikannya.

| Field | Tipe | Rules |
|---|---|---|
| `command_id` | string | Wajib. Agent membalas dengan `CommandAck` membawa id yang sama |
| materi kunci | — | Tidak pernah dicatat pada sisi mana pun |

Security: authn=mTLS-client-cert; authz=hanya-agent-milik-project; konfirmasi=CommandAck-wajib; logging=materi-kunci-tidak-pernah-dicatat

## Aturan evolusi

- Setiap perubahan `.proto` diikuti `./scripts/gen-proto.sh`; hasil di `shared/agentpb/` di-commit.
- Nomor field tidak boleh dipakai ulang; tandai `reserved` seperti field 5 pada `Hello`.
- Field baru bersifat opsional secara default di proto3; agent lama akan mengabaikannya.
- Menambah jenis agent ketiga tidak memerlukan service baru — tambahkan varian ke oneof dan biarkan jenis lain mengabaikannya.

## rpc: DownloadMalwareDatabase

Server-streaming RPC untuk corpus hash global. Memakai interceptor mTLS yang sama
seperti `Stream`; sertifikat wajib terdaftar dan aktif. Corpus ini bukan data
project dan tidak mengandung Auth-Key, upload pengguna, atau aturan tenant.
`MalwareDatabaseRequest` kosong; tidak menerima path/URL dari agent.

| Field | Tipe | Rules |
|---|---|---|
| request | `MalwareDatabaseRequest` | Kosong; wajib kredensial mTLS aktif |
| `data` | bytes | Maksimal 64 KiB per chunk; total maksimal 128 MiB |
| `sha256` | string | Hanya frame akhir; digest cocok dengan seluruh data dan diikuti EOF |

Server membaca snapshot file yang dibuka sekali, mengirim chunk `data` maksimal
64 KiB, lalu satu frame akhir `sha256` tanpa data. Total maksimal 128 MiB.
Agent wajib menerima checksum yang cocok dan akhir stream sebelum memvalidasi
record SHA-256 serta mengganti file secara atomik. Kegagalan mempertahankan file
lama. Transfer agent dibatasi dua menit dan satu transfer aktif per proses.

`FetchSecurityData.malware_from_control_plane` (field 4) mengarahkan komponen
`malware` ke RPC ini, bukan mengirim kredensial provider. WAF agent juga melakukan
sinkronisasi saat reconnect dan melaporkan komponen `malware` dalam `secdata:status`.
Selesaikan upgrade control plane dan WAF agent untuk alur terpusat; agent lama
mengabaikan field baru dan masih memerlukan konfigurasi fetch lama. Selesainya
update di control plane bukan bukti bahwa seluruh agent telah selesai menerapkan.

Security: authn=mTLS-client-cert; authz=credential-aktif; tenancy=corpus-global-tanpa-data-tenant; transport=TLS-wajib; audit=admin.security_data_updated
