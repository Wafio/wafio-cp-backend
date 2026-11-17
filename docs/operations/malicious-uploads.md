# Malicious Uploads Detection

This guide covers the current SHA-256 upload scanner. Public documentation is available at [WAFio upload protection](https://wafio.cloud/docs#malicious-uploads).

## Provider setup

1. Obtain an Auth-Key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/). See the [MalwareBazaar export requirements](https://bazaar.abuse.ch/export/). The key belongs to abuse.ch, not WAFio licensing or agent authentication. Under the abuse.ch terms, commercial use of MalwareBazaar data is subject to a Spamhaus subscription.
2. As a system administrator, open **Admin → Security Data → MalwareBazaar**. Paste the key value and save. If the key was downloaded in a file, copy its value, not the download URL or account password.
3. Select **Check access & update hashes**. Inspect the update log and each connected WAF agent's database status. Verify its source and hash count before enforcing a policy.

The control plane encrypts the stored provider credential and downloads hash lists. Compatible WAF agents receive the database over authenticated connections, verify its checksum, and replace it atomically. Agents do not receive the provider key. Uploaded files are inspected locally and are not submitted to MalwareBazaar. The Security Data update action is manual; saving a key does not establish a refresh schedule.

## Project policy

Open the project's WAF configuration, select **Malicious Uploads Detection** in the settings navigation, enable scanning, and save. Connected agents receive configuration updates without requiring a restart.

| Setting | Behavior |
| --- | --- |
| When malware is detected | Block rejects confirmed matches with HTTP 403; Log only records them and forwards the request. |
| When scanning is incomplete | Forward and log is the default. Reject upload blocks in enforcement mode; Forward with scan details does not escalate to a content-scan log action. Log only mode converts incomplete-scan blocking to logging. |
| Maximum scan size | Default 10 MiB (10,485,760 bytes), shared across all files and fields in a request. Only complete files within the remaining budget are hash-matched. |
| Multipart files | Enabled by default; individual file parts are inspected. Processing is limited to 128 parts. |
| Raw request bodies | Disabled by default; enable to hash the entire non-multipart body for applicable endpoints. |
| Custom hashes | SHA-256 allowlist entries take precedence over custom blocklist and downloaded malware hash matches. They do not bypass other WAF protections. |

The JSON configuration uses `content_scan.mode` (`block`, `log`, or `disabled`) for matches and `content_scan.on_incomplete` (`log`, `allow`, or `block`) for incomplete scans. Omitting `on_incomplete` means `log`. Disabling this feature does not disable other WAF policies or application validation.

For an availability-first rollout, start in Log only with Forward and log, inspect real upload sizes and outcomes, verify feed synchronization, and then enable blocking for confirmed matches.

## Missing database and coverage

The offline fallback contains only the EICAR test signature. **EICAR-only fallback is currently not treated as an incomplete scan.** A successful EICAR test verifies the detection path, not installation of the full malware feed. A no-match result against this fallback provides no broad malware coverage.

When the engine reports an unavailable database, parsing error, unsupported content encoding, truncated input, or scan size/part limit, `on_incomplete` governs the result. The same policy applies when the WAF agent could not decode a request body for the text engines (unsupported or corrupt `Content-Encoding`, decode size cap): with content scanning enabled and `on_incomplete` omitted, such requests are now logged as `ContentScanIncomplete` instead of being allowed silently; set `allow` to keep the previous coverage-only behavior. A body left undecoded because the agent's process-wide decode memory budget was busy is load-related, not request-related: it is logged at most, never blocked. Rejection of an incomplete scan is not a malware verdict. Other WAF rules and the upstream application may still reject a forwarded upload.

Bloom screening is followed by an exact SHA-256 lookup; a Bloom candidate alone cannot trigger a malware match. This removes Bloom-filter false positives from the verdict, not all possible threat-intelligence errors. Unknown or modified malware can have no match. Archives are not unpacked. Partial content is not hash-matched as a complete file.

## Verification checklist

Use a controlled test application. Other WAF policies must be considered when interpreting HTTP responses.

| Scenario | Expected result from content scanning |
| --- | --- |
| Scanning disabled, ordinary file or EICAR | No content-scan rejection. |
| Enabled, Block, exact known hash / EICAR | HTTP 403; confirmed malware match recorded. |
| Enabled, Log only, exact known hash / EICAR | Forwarded with detection log. |
| Enabled, complete file with no matching hash | No content-scan rejection; not a safety guarantee. |
| File exceeds budget, Forward and log | Forwarded with incomplete-scan result. |
| File exceeds budget, Reject upload, Block mode | HTTP 403 with incomplete-scan classification, not malware. |
| File exceeds budget, Reject upload, Log only mode | Forwarded with incomplete-scan log. |
| EICAR-only fallback, unmatched file | No match; verify feed installation separately. |

Compare upstream receipt and file integrity, not only status codes. Check agent database source, hash count, synchronization status, and control-plane update logs separately from policy tests.

## Implementation references

- [Scanning configuration and complete-file hashing](../../internal/engine/content_scan.go)
- [Verdict and incomplete-scan policy handling](../../internal/application/analyze.go)
- [Engine tests](../../internal/engine/content_scan_test.go)
- [Pipeline policy tests](../../internal/application/content_scan_pipeline_test.go)
- Control-plane settings UI: `src/lib/components/MalwareProviderSettings.svelte` in wafio-cp-frontend
- Project settings UI: `src/lib/components/ConfigWafForm.svelte` in wafio-cp-frontend
