# Internal Architecture (Hexagonal)

Struktur `internal/` di WAFio mengikuti pola **Hexagonal Architecture (Ports & Adapters)** dengan pemisahan jelas antara domain, use case, dan infrastruktur.

## Layering

- `domain/`  
  Entitas inti, interface port, dan kontrak bisnis yang bebas framework.

- `application/`  
  Use case / orchestration logic yang menggabungkan domain + port.

- `adapter/`  
  Implementasi adapter untuk masuk/keluar sistem (TCP, WAF analyzer, block store, rate limit, dll).

  Subgroup penting:
  - `adapter/http` (package `httpadapter`) untuk delivery HTTP/Fiber.
  - `adapter/repository` (package `repository`) untuk persistence adapter.

## Supporting Bounded Context

- `engine/` → Membaca, memvalidasi dan menormalkan `rules_json`; pemeriksaan custom rule dan script rule saat disimpan; halaman block dan challenge bawaan. Tidak ada kode deteksi di sini.
- `ratelimit/`, `usage/`, `tier/`, `validate/`, `otp/`, `email/`, `geo/`, `siem/`, `projectlog/`, `dashboard/` → modul fitur pendukung yang tetap dipakai lewat kontrak domain/application.

## Dependency Direction

Aturan dependensi yang dijaga:

1. `domain` tidak bergantung ke package infra/framework.
2. `application` bergantung ke `domain` + port interface.
3. `adapter/*` boleh bergantung ke `application/domain`, bukan sebaliknya.
4. Komposisi wiring dilakukan di `cmd/wafio`.

## Conventions

- Hindari hardcode path runtime di adapter; baca dari config (`config.yaml`/env).
- Simpan output build di luar root source tree (disarankan `bin/`).
- Pertahankan package kecil dengan tanggung jawab tunggal.
