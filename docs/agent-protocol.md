# gRPC contract: Agent Control

Source: `shared/proto/agent/v1/agent_control.proto`. The generated code is in `shared/agentpb/` and must not be edited by hand.

One service, two RPCs, two kinds of agent. Authentication happens entirely in the TLS layer.

## Authentication model

Every table below assumes this and does not repeat it:

- TLS with `tls.RequireAndVerifyClientCert` against the control plane's own CA.
- The SHA-256 of the client certificate is looked up in `mtls_credentials` to map the connection to exactly one `project_id`.
- There is no second authentication layer. `agent_name` and `host_key` inside `Hello` are lookup keys, not credentials.
- A connection without a valid client certificate is closed during the handshake, before any application message is read.

## rpc: Stream

One bidirectional stream per agent process. The first message from the client must be `Hello`.

| Param | Type | Rules |
|---|---|---|
| client certificate | X.509 | Required. The chain is verified against the CA. The SHA-256 fingerprint must be in `mtls_credentials`, otherwise the stream is refused (`Unauthenticated`). The credential is checked again when the stream opens and every 5 minutes; revoking a credential (`DELETE .../agent-grpc-credentials/{credId}`) ends every stream that uses it at once with `Unauthenticated`; deleting a project (or deleting the user that owns it) ends the streams of all credentials of that project. The credential is also read again after `Hello` is validated, before `Welcome` and the first bundle, so a revoke in the middle of `Hello` accepts nothing. A `DownloadMalwareDatabase` download is tracked like `Stream` and stops at the next chunk after a revoke or a project delete. The server sends GOAWAY after a connection age of 24 hours (+5 minutes grace); the agent reconnects and authenticates again |
| first message | `AgentMessage` | Must hold the oneof variant `hello`. A first message of another kind ends the stream |
| compression | n/a | The stream is not compressed at transport level (grpc-go decompresses before the handler, so the allocation cannot be charged). Host agent v1.9.0+ compresses telemetry batches itself (`CommandAck.payload`, see the CommandAck event) after the control plane announces `telemetry_gzip` |
| receive budget | n/a | v1.9.0+. Every message is charged to the account that owns the project at its size, and a gzip payload at its original size (up to 64 times its length) before it is decompressed: 64 MiB/s per account, with a burst of one second; accounts that were active in the last 2 seconds share a process-wide total of 128 MiB/s, max-min fair (both can be configured). While in debt, the stream of that account does not read the next message (flow control slows its agent) and asks again after at most 1 second; the agent's `last_seen` is still refreshed 30 seconds after the last heartbeat; nothing is refused. `Hello` must be at most 64 KiB (`InvalidArgument`); at most 16 streams per connection |
| `hello.agent_name` | string | An agent already registered in the project reconnects with its row (an agent that was deleted, by soft delete, is not recognised any more). A name not yet known is registered automatically for both kinds (the WAF agent installation script only sets the name and does not call the register API), at most 20,000 live agents per project; beyond that `ResourceExhausted` |
| `hello.agent_version` | string | Free text; used for fleet version reports |
| `hello.hostname` | string | Free text; used for display |
| `hello.bundle_generation` | int64 | WAF agent only. Informational: the server always sends an initial bundle on connect |
| `hello.host_key` | string | Optional. When not empty it is verified against the `hosts` table, also for an agent that is already registered (it used to be ignored for a known host agent), and must belong to that project and not be revoked, otherwise `PermissionDenied` "invalid host_key". A check that cannot run (database error, no argon2id verification slot before the 3 second `Hello` deadline) gives `Unavailable` and the agent retries. A key that was verified before against the same stored hash does not run argon2id again. The key is found by id lookup (128 bits of the SHA-256 of the whole key, migration 000105); a key stored before 000105 is found by its display prefix and every candidate is verified, so two hosts that share a 20 bit prefix no longer refuse each other. A valid key binds the agent to that host |
| revoked host | n/a | An agent bound to a revoked host, or, without a host, whose `hello.hostname` is the name (or reported hostname) of a revoked host and not that of any live host, is refused with `PermissionDenied` "host revoked". A stream that was not bound to a host at `Hello` (a WAF agent linked by hostname in the background) looks up its agent's host again at the periodic re-check. Revoking or deleting a host (`POST …/hosts/{hostId}/revoke`, `DELETE …/hosts/{hostId}`) closes the streams of that host's agents at once with the same code; the host is also read again after `Hello` is validated (before `Welcome`) and with the credential re-check every 5 minutes. The project-wide mTLS credentials are not revoked with it; credentials enrolled with the host key of that host are deleted with it (see "Host-bound credentials") |
| `hello.agent_kind` | string | Hint: `waf`, `host` or `ebpf`. Ignored when the agent is already registered |
| `hello.features` (field 8) | repeated string | Optional. Capabilities of the agent binary; names that are not known are ignored. The WAF agent sends two kinds of names: `script_rules` (`engine.FeatureScriptRules`) when it can run script rules, `no_script_rules` (`engine.FeatureNoScriptRules`) when it cannot (an earlier agent build without scripts); a script rule then leaves every request of that app unfinished, which becomes LOG; and `maintenance_mode` (`engine.FeatureMaintenanceMode`) when it answers the requests of an app in maintenance mode with the maintenance page itself. The control plane stores the script rules value as `agents.script_rules` (migration 000116; `false` for `no_script_rules`, `true` when the agent sends `script_rules` or another name, null when there is no feature or the agent is a host agent), refuses with 400 `SCRIPT_RULES_UNSUPPORTED` to create or enable a script rule for an app whose agents all report `script_rules: false` (a script rule that is already enabled can still be edited and switched off), and shows it as `script_rules` in the agent API objects (the WAF fleet agent list, the agent of an app); the value is rewritten on every connection. The control plane stores whether the agent supports maintenance mode as `agents.maintenance_mode` (migration 000119; `true` when the list holds `maintenance_mode`, `false` for any other non-empty list, null when there is no feature or the agent is a host agent), refuses with 409 `MAINTENANCE_UNSUPPORTED` to turn maintenance mode on for an app whose agent reports `false`, refuses the same way to move an app that is in maintenance mode to a different agent that reports `false` (`PUT /apps/{appId}/waf-agent`; an agent that never connected is let through, changing only the mode on the agent that serves the app is not a move, and an agent that connects later with an older build cannot be refused, so the app's maintenance settings then report `agent_supported: false`), and shows the switch as `maintenance_enabled` in the app and agent route objects; the value is rewritten on every connection too. The bundle carries `apps[].maintenance` (the stored maintenance object of the app: `enabled`, `message`, `end_time`, `custom_html`, `allow_ips`, `allow_paths`, `started_at`) only while the app is in maintenance mode, and an agent that does not know the key ignores it. The bundle does not depend on features: every agent receives the same bundle, the result of `engine.NormalizeBundle` (version 1 document keys are rewritten: `inspection_off` replaces `disable_semantic` and `disable_rule_based`, `skip_coraza_when_clean` is dropped, tuning rules with engine `crs` are dropped, `scan_mode` `crs_only` and `semantic_only` become `default`, `skip_crs` is dropped). The stored configuration is not changed, and the server logs each rewrite once per app and per connection. Names sent by a v1 agent (`semantic_only`, `semantic_keys_jwt_graphql`, `field_rules_v2`, `custom_rule_field_paths`) are ignored. A v1 agent older than v1.9 does not know the keys `jwt` and `graphql` in `semantic_override` and `skip_semantic`, so it refuses a bundle that holds them and keeps serving the cached bundle. The host agent (v1.9.0+) sends `telemetry_demand`: it handles the `BundleUpdate` `telemetry:demand` (see the BundleUpdate event). A host agent with a trace forward filter sends `trace_forward_filter` (`domain.TraceForwardFilterFeature`): it handles the `BundleUpdate` `trace:forward_filter`. A WAF agent that serves apps over TLS from the bundle sends `tls_certificates` (since `shared/v0.2.0`): it accepts `CertificateInstall` and sends `CertificateStatus` (see those events); this control plane does not act on the name yet |
| field 5 | n/a | `reserved`. The field number must not be reused after `waf_key` was dropped in migration 000017 |

### Host-bound credentials (host key enrollment, migration 000108)

A credential created on the Credentials page is valid for the whole project (`mtls_credentials.host_id` NULL) and follows the `Hello` rules above unchanged. A credential from `POST /api/internal/host-enroll` is issued for one agent (kind and name) on one host; the authentication interceptor puts its binding (host, kind, name) in the stream context and `validateHello` runs `validateBoundHello`. The server holds that credential to exactly its identity:

| Rule | Effect |
|---|---|
| `hello.agent_name` | Must equal the enrolled name; empty counts as `<hostname>@ebpf` (the same derivation as the project path). Anything else gives `PermissionDenied` |
| `hello.agent_kind` | The hint `waf` means WAF; anything else (empty, `host`, `ebpf`) means host. Must equal the enrolled kind, otherwise `PermissionDenied` |
| host | Must exist in the project and not be revoked. A read error gives `Unavailable` (fail closed; the project path accepts on error). Revoking or deleting a host already deletes its credentials, so this is a second layer |
| `hello.host_key` | When sent it must verify and belong to the bound host, otherwise `PermissionDenied` |
| agent row | The row with that name and kind on the bound host, or a new row on that host when the project has no agent with that name. Another row with the same name (another host, no host, or another kind) gives `PermissionDenied`; a row that is not attached to a host is NO LONGER adopted |
| rejection audit | A rejected `Hello` is recorded as `agent.rejected` (metadata `reason` = `agent_name` \| `agent_kind` \| `host_revoked` \| `host_key_invalid` \| `host_key_other_host` \| `agent_name_conflict`, `credential_id`, `host_id`, `agent_kind`, `agent_name`, `presented_name`, `presented_kind`, `presented_hostname`, peer IP), at most once per credential and reason every 10 minutes |

As a result a machine with an enrolled credential cannot reconnect under another name, another kind, or for another host, whatever hostname it reports. What remains: a project-wide credential can still do it (revoke it on the Credentials page).

Security: authn=mTLS-client-cert; authz=fingerprint-to-project-mapping; tenancy=project_id-from-fingerprint; transport=TLS-required; replay=not-applicable-long-lived-stream; audit=agent_audit

Connection:

- Server keepalive: a ping after 60 seconds without activity; the connection is closed if it is not answered within 20 seconds. Enforcement policy: a client may ping at most every 15 seconds (also without an active stream); more often than that and the connection is closed (`too_many_pings`).
- Client keepalive (WAF and host agents): a ping every 30 seconds while the stream is active, timeout 10 seconds.
- `Welcome.agent_id` is `agents.id`, the id that the dashboard and the API show, not the id of the mTLS credential. Empty when the WAF agent row was not registered yet at `Hello`.
- Agent reconnect: exponential backoff from 1 to 30 seconds with ±20% jitter, so a control plane restart does not make every agent reconnect in the same second.
- Control plane shutdown: `GracefulStop` for at most 10 seconds, then `Stop()` cuts the remaining streams; agents reconnect as usual.

## event: Heartbeat

Agent to server. Sent by both kinds of agent at the interval negotiated through `Welcome.heartbeat_seconds`.

| Field | Type | Rules |
|---|---|---|
| `unix_time` | int64 | Seconds since the epoch on the agent. The difference from server time shows on the dashboard |
| `decisions_total` | uint64 | Monotonic counter since the agent started |
| `blocks_total` | uint64 | Monotonic counter; must not exceed `decisions_total` |
| `host_info_json` | bytes | JSON-encoded HostInfo snapshot. Sent in the first heartbeat after connect and every 5 minutes. Empty when unchanged. The host agent includes `ssh_ports` (the TCP listener ports of sshd/dropbear that were detected); the control plane's firewall lockout guard requires one of them to stay open (without `ssh_ports`, 22 is assumed, with the warning `SSH_PORT_ASSUMED`) |
| `analyze_panics_total` | optional uint64 | WAF agent only (v1.2+). Panics caught during request analysis; the request is allowed without full inspection |
| `engine_panics_total` | optional uint64 | WAF agent only (v1.2+). Panics of a semantic engine caught inside a scan |
| `partial_coverage_total` | optional uint64 | WAF agent only (v1.2+). Requests whose semantic scan coverage was not complete, so the request is marked partly uninspected |
| `parse_budget_exhausted_total` | optional uint64 | WAF agent only (v1.2+). Scans that skipped relaxed-parse variants because the work budget ran out |
| `bundle_source` (field 9) | optional string | WAF agent only (v1.3+). Where the configuration in force came from: `live` (from this stream), `cache` (`last-bundle.json`, loaded at start), `cache_stale` (the cache is older than `--bundle-cache-max-age`, default 7 days; it is still applied). Not set = no bundle yet |
| `bundle_generation` (field 10) | optional int64 | WAF agent only (v1.3+). The bundle generation in force; set together with `bundle_source` |
| `script_incomplete_total` (field 11) | optional uint64 | WAF agent only (v1.4+). Script rule evaluations that did not finish (timeout, sandbox limit, panic, runtime error, request budget exhausted); the worst verdict is LOG |
| `script_errors_total` (field 12) | optional uint64 | WAF agent only (v1.4+). The runtime error part of field 11 |
| `script_rules_rejected_total` (field 13) | optional uint64 | WAF agent only (v1.4+). Script rules dropped when the bundle was loaded because they use a builtin outside the allowlist |
| `script_runs_in_flight` (field 14) | optional int64 | WAF agent only (v1.4+). Gauge: script runs whose goroutine has not finished. The server stores a negative value as 0 |
| `agent_panics_total` (field 15) | optional uint64 | WAF agent only (v1.4+). Other panics caught by the agent (WebSocket relay, IP jail enforcement); analysis and engine panics are in fields 5 to 6 |
| `analyze_latency_p50_us` (field 16) | optional uint64 | WAF agent only (v1.4+). p50 of the analysis latency over the last 5 minutes, in microseconds, estimated from a histogram (buckets 0.25/0.5/1/2/5/10/25/50/100/250/1000 ms; a value in the overflow bucket = 1 s). Not set when `analyze_latency_samples` = 0 |
| `analyze_latency_p95_us` (field 17) | optional uint64 | WAF agent only (v1.4+). p95, same rules as field 16 |
| `analyze_latency_p99_us` (field 18) | optional uint64 | WAF agent only (v1.4+). p99, same rules as field 16; inline target < 5 ms |
| `analyze_latency_samples` (field 19) | optional uint64 | WAF agent only (v1.4+). Number of analyses in the 5 minute window (0 = no traffic) |
| `regex_rules_dropped_total` (field 20) | optional uint64 | WAF agent only. Custom GUI/tuning rules dropped when the bundle was loaded because the regex is not valid or its program has more than 256 instructions, cumulative since the agent started. Stored in `agents.waf_regex_rules_dropped_total` (migration 000097); the rule list marks each such rule with `regex_error` |

The inspection health counters (fields 5 to 8, 11 to 13, 15, 20) are cumulative since the agent process started and return to zero on restart; field 14 is a gauge and fields 16 to 19 summarise a sliding 5 minute window. `optional` fields give explicit presence: an old agent (or a host/eBPF agent) does not set them, and the server leaves the stored value as it is (NULL = "not reported yet", not zero). The server stores the last value in columns of `agents` (fields 5 to 8: migration 000086; fields 11 to 19: migration 000096; field 20: migration 000097) and returns it in `GET /api/fleet/agents`. Upgrade the control plane first; an old agent simply does not set the new fields.

`bundle_source` and `bundle_generation` (fields 9 to 10) are stored in `agents.waf_bundle_source` and `agents.waf_bundle_generation` (migration 000099) in the same `UPDATE` and returned in `GET /api/fleet/agents` as `bundle_source` and `bundle_generation`. The server accepts only `live`, `cache`, `cache_stale` and `""` for `bundle_source`; any other value is stored as `unknown`. A negative generation is stored as 0. A change of source is still logged per stream.

Security: authn=mTLS-client-cert; authz=project-from-fingerprint; ratelimit=interval-set-by-server-through-Welcome; audit=last_seen-updated

## event: WAFDecisionEvent

WAF agent to server. One event per HTTP request that the inline proxy analysed. An eBPF agent never sends it.

| Field | Type | Rules |
|---|---|---|
| `ts_unix` | int64 | Time of the decision on the agent |
| `method`, `host`, `uri` | string | Request context as received |
| `remote_ip` | string | The client address as resolved by the agent; honours the trust-proxy switch on the agent |
| `status` | int32 | HTTP status code the client received: a block or challenge response, the upstream response, 502 for an upstream error. 0 = not recorded (an old agent, or an event without a status such as a WebSocket handshake log). Stored in `waf_decisions.status` (migration 000117; NULL for 0) and answered by the API as `status`, 0 when NULL |
| `score` | int32 | Decision score. The default block threshold is 150 and the default log threshold 80 |
| `action` | string | Required, one of `allow`, `block`, `monitor` |
| `categories` | repeated string | Attack categories from the rule map |
| `match_detail` | string | The excerpt that triggered the detection |
| `analyze_method` | string | Which layer decided; becomes `waf_decisions.analyze_method`. `rule_based` and `hybrid` from a v1 agent are stored as `semantic`; old rows are not rewritten, but the API shows and counts them as `semantic` |
| `app_id` | string | May be empty for host-header traffic that maps to no app |
| `user_agent`, `content_type` | string | Request context |
| `body_size` | int32 | Body size before truncation |
| `body_preview` | string | The start of the body (512 characters); values of form/JSON/multipart fields with a secret name become `[redacted]`, as in `request_body` |
| `cwe` | string | From the taxonomy map; empty when the detection has no CWE mapping |
| `latency_us` | int32 | Decision latency in microseconds |
| `match_source` | string | For example `header:User-Agent`, `body`, `query:id`, `body:password`, `body.json:password`, `path` |
| `request_headers` | map of string to string | Filtered before sending: `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` are dropped, values of headers with a secret name (`X-Api-Key`, `X-CSRF-Token`, `X-Amz-Security-Token` …) become `[redacted]`; a header that an exact `match_source` names (`match_source_exact`) stays, reduced for a JWT/Anomaly verdict (Authorization: the scheme + the header segment of the JWT; Cookie: only the named cookie); a guessed source does not exempt secret values. The control plane filters again at ingest for old agents |
| `request_body` | string | The first 4096 bytes; empty when binary. Values of form fields, JSON keys (any depth) and multipart text fields with a secret name become `[redacted]`, except the field that an exact `match_source` names |
| `query_params` | string | The query string; values of parameters with a secret name (`api_key`, `token`, `access_token`, `password` …) become `[redacted]`, except the parameter that an exact `match_source` names. The query string in `uri` is filtered the same way |
| `payload_type` | string | For example `json`, `xml`, `form-urlencoded` |
| `coverage` | string | v1.2+. Coverage gap flags of the semantic scan, separated by commas (for example `field_cap,body_binary`); the same as the `coverage:<flags>` marker in `match_detail`, but also set for `allow`. Empty = complete coverage or an old agent. Stored in `waf_decisions.coverage`. The flag `engine_disabled:<key>` marks an engine that the operator switched off for that request (all twenty keys): information, not a gap, so it does not raise the verdict and is not in the `coverage:` marker of `match_detail`. The flag `engine_log_only:<key>` marks an engine whose `action` is `log` and whose blocking detection was held back as LOG on that request (the request is forwarded; category, score and detail are the same as the block would have had); like the previous flag it is information, not a gap. The API splits this text: `coverage` holds the gap flags only, `engines_off` the keys of engines that were switched off and `engines_log_only` the keys of engines that were held back, for new and old rows |
| `match_source_exact` | bool | v1.9+ (field 25). `true` when the engine itself names the `match_source` input (semantic, content scan); `false` for a guessed source (the whole URI), a source with no input, and old agents. Only an exact source keeps a value with a secret name; the control plane filters again at ingest using this value. Not stored |

Sampling is done on the agent side so the stream is not flooded.

Security: authn=mTLS-client-cert; authz=project-from-fingerprint; pii=sensitive-headers-filtered-before-send; retention=30-day-hypertable; audit=waf_decisions-append-only

## event: CommandAck

Used by both agents for two different purposes. This is a deliberate compromise and is documented in the proto.

| Field | Type | Rules |
|---|---|---|
| `command_id` | string | WAF agent: matches the `command_id` of `KeyRotation`. eBPF agent: the literal `ebpf:telemetry` |
| `ok` | bool | WAF agent: true when the rotation succeeded. eBPF agent: always true for telemetry |
| `error` | string | WAF agent: a real error message. **eBPF agent: the JSON `PushPayload`, not an error.** This field is reused so the proto schema did not need to change |
| `payload` (field 4) | bytes | v1.9.0+, host agent only with `command_id="ebpf:telemetry:v2"`: gzip of the JSON `PushPayload` (in place of `error`), sent only on a stream whose control plane announced `telemetry_gzip` (`telemetry:demand`). The control plane reads the original size from the gzip trailer (ISIZE, up to 8 MiB and up to 64 times the member length, `telemetrygz.MaxRatio`), charges it to the account receive budget before decompressing, and requires a matching size and CRC; a payload that is damaged, above that ratio or on a stream without the announcement is dropped without ingest (one above the ratio and without the announcement is also dropped without a charge), and the stream keeps running. The agent pads a member that would compress more than 64 times with empty stored deflate blocks (5 bytes each, no output) until its length is 1/64 of the batch (`telemetrygz.Encode`), so a legitimate batch is never refused because of its ratio; any gzip reader reads it as the same batch |

A telemetry v2 batch (`ebpf:telemetry:v2`, holding a `batch_id`) is deduplicated per (project, agent, `batch_id`) and answered with `BundleUpdate{command_id="ebpf:telemetry:receipt"}`. The receipt of an accepted batch is kept for 2 minutes in a shared pool of 131,072 entries (retry progress per section 65,536 entries) that is shared fairly between projects: when it is full, the project that holds the most entries releases its oldest. A flood of small batches with new `batch_id` values from one project only shortens the deduplication window of that project itself (a late resend of its batch may be stored twice) and no longer makes batches of other projects refused (`process_accepted: false`, "receipt capacity exhausted"). The WAF decision writer queue (8,192 rows) and the block window queue (1,024) are also shared fairly per project and served round-robin.

Security: authn=mTLS-client-cert; authz=project-from-fingerprint; integrity=payload-accepted-only-in-authenticated-stream; audit=telemetry-ingested-into-hypertable

## event: BundleUpdate

Server to agent. Carries configuration, never code.

| Field | Type | Rules |
|---|---|---|
| bundle body | JSON | WAF agent: the WAF rule document; `apps[].fcgi_keep_conn` is in it only when it is `true` (the application keeps its FastCGI connection open between requests). An agent that does not know the key ignores it: agents before 2.1.1 keep FastCGI connections open whatever the setting, and 2.1.1 closes each one after the reply. eBPF agent: the desired state and trace policies |
| firewall lockout guard | n/a | The eBPF agent runs the same guard as the control plane and the local API (`hostpolicy.ValidateHostFirewall`) before it changes any map. A refused state is acknowledged with an `error` that starts with `apply refused (<CODE>): …`; the control plane shows it as `bundle_status.status = "refused"` with `code`, and the last policy that succeeded stays in force. The agent keeps the last policy that succeeded together with its generation and the pinned control plane endpoint (`/var/lib/wafio-host-agent/firewall-last-good.json`, backup `/run/wafio/…`, the newer wins; override `WAFIO_FIREWALL_STATE_FILE`) and applies it again at start before the stream connects: the control plane is resolved first (or the stored endpoint is seeded); when neither exists, the stored egress Deny All is applied with DNS allowed until the endpoint is pinned. After `Hello` the agent sends `CommandAck{command_id="ebpf:policy_source"}` (JSON `{"source":"saved\|default\|live","generation":…,"dns_relaxed":true?}` in `error`) → `bundle_status.source` / `saved_generation` / `dns_relaxed` (a stored egress Deny All runs with DNS allowed because the control plane endpoint is not pinned yet). The server always sends the desired state, also an empty one: a part that is not stored is sent explicitly (empty list, port policy off, default agent config), so an empty state = a reset. An eBPF object without an exception for the map `wafio_cp_endpoints` refuses egress Deny All and blocklist entries `0.0.0.0/0`/`::/0`. Apply does not flush conntrack |
| control plane endpoint | n/a | Before every dial, the host agent resolves `--grpc-server`, writes the address:port to `wafio_cp_endpoints`, then dials exactly that endpoint (target `passthrough:///`, no gRPC DNS resolver). A failed resolution = the previous endpoint stays in use |
| generation | int64 | Monotonically increasing. The agent stores it and sends it back through `Hello.bundle_generation`. WAF agent: the generation comes from one sequence for all agents (migration 000102), so an agent that registers again never receives a lower generation; the WAF bundle carries `agent_id` and the agent refuses a lower generation only for the same `agent_id` (a bundle with another `agent_id` starts a new sequence). A WAF configuration bundle that fails to apply (observer not ready, port temporarily in use) is retried by the agent with backoff of 2 s to 60 s, at most 10 times, and acknowledged again `ok` with the same `command_id` once it succeeds; a newer bundle or a broken stream cancels it. Host agent: a lower generation is refused; the same generation with other content is applied (the latest content on an ordered stream is the control plane's view) |
| target | n/a | A WAF bundle is sent only to the WAF agents of that project; a host/eBPF agent never receives it |
| WAF bundle size | n/a | The WAF agent accepts a `ServerMessage` of at most 4 MiB (4,194,304 bytes, the decoding limit of its gRPC client, which the agent sets explicitly as `MAX_SERVER_MESSAGE_BYTES`). A larger message fails on the agent with an out-of-range error and ends the stream; the agent reconnects, the control plane sends the same bundle again at connect, and so the agent keeps its last bundle, never receives a newer one, and loses its telemetry at every cycle. The control plane therefore keeps every WAF bundle at or below `engine.MaxAgentBundleBytes` (4,193,280 bytes; the envelope around the bundle is under 128 bytes) wherever it can refuse the change that would pass the limit: turning maintenance mode on, or saving its settings while it is on, answers 409 `MAINTENANCE_BUNDLE_TOO_LARGE` (with `field: custom_html` when the save holds a custom page), moving an app that is in maintenance mode to another agent answers the same code, and so does a route change (`PUT /apps/{appId}`, `PUT /agents/{agentId}/routes/{appId}`) that gives an app in maintenance mode a listen port and an upstream for the first time (an app without both is not in the bundle, so its page counts only from then on). These checks lock the bundle of the agent (a transaction advisory lock), so two of them for one agent are measured one after the other. The size is that of the bundle as sent, after `engine.NormalizeBundle`, measured with the same code that builds it; each of `<`, `>` and `&` in a maintenance page takes six bytes in it, so a custom page of 64 KiB can take 384 KiB, and ten such pages fill one agent. Turning maintenance mode off is never refused. Growth of the bundle through rules and custom rules, and the creation of routes, are not checked against the limit. |
| `command_id="telemetry:demand"` | JSON `{"live_for_sec":N,"telemetry_gzip":true,"status_on_demand":true,"status_live_for_sec":M}` | Only to a host agent that reports `hello.features` `telemetry_demand`. Not configuration: the agent does not acknowledge it and does not store a generation. `telemetry_gzip: true` makes the agent send telemetry batches as gzip `CommandAck.payload` on that stream. On connect N = the remaining live viewer window of that agent (0 when there is none; snapshot of connections and bandwidth every 60 seconds); `N = 120` while the Firewall page reads a snapshot, matched per project and agent, at most once per 30 seconds per agent (a snapshot every 3 seconds during the window; the agent caps it at 600 or less). Status on demand: `status_on_demand: true` (always from this control plane) makes the agent send the slow payload (host info, status, trace stats, rule hit counts) every 3 seconds and metrics every 1 second only during the status window of M seconds or the snapshot window of N seconds, and otherwise both every 30 seconds; the slow payload is also sent at once on connect, when a window opens and after a configuration bundle is applied. On connect M = the remaining status window (at least the remaining snapshot window, 0 when there is none); `M = 120` while the dashboard reads status (`/host/stream` channels `status`/`metrics`/`stats`/`hostinfo`, `GET …/host/status`, `…/host/metrics`, `…/host/trace/status`, `…/host/trace/stats`), at most once per 30 seconds per agent; a snapshot request carries `N = M = 120`. A message without `status_on_demand` (an old control plane): every 3 seconds / 1 second as before. An agent without that feature never receives it |
| `command_id="trace:forward_filter"` | JSON `{"revision":R,"digest":"<32 hex>","filter":{"rules":[…],"correlation_stages":[…]}}` (up to 1 MiB), or the marker `{"revision":R,"digest":"<32 hex>","disabled":"too_large"}` when the filter is larger than 1 MiB | Only to the stream of a host agent (kind `host`/`ebpf`) that reports `hello.features` `trace_forward_filter`: the detection rules and correlation stages that ingest evaluates for that host. Not configuration: the agent does not acknowledge it, does not store a generation and does not save it to disk; the filter applies to that stream only. Every telemetry batch of the agent over gRPC carries `trace_forward` `{"digest":"…","rule_hits":{"<rule id>":n}}`: the digest of the filter the stream holds (empty = none yet) and the rule hits of events that were not sent; the control plane sends the filter again when the digest differs (at once when its content changes, otherwise at most every 10 seconds), and straight to the connected stream after every write of a detection rule of that host or of a correlation chain of its project. The `too_large` marker: the agent does not filter and reports the digest of the marker (status `too_large`), so it is not sent again. A filter with another `revision`, a digest that does not match its content, or broken JSON is not applied (the agent sends all events) |
| send timeout | n/a | The server sends outside the registration lock, in parallel per stream, with a timeout (default 10 seconds). A stream whose `Send` blocks past the limit is cut (`UNAVAILABLE`); the agent reconnects |
| agent cache | n/a | The WAF agent writes every bundle that it applied successfully to `$STATE_DIRECTORY/last-bundle.json` (or `--state-dir` / `WAFIO_STATE_DIR`; temp + fsync + rename, mode 0600) and applies it at start before it connects. A damaged file is ignored |
| executable code | n/a | Forbidden. A compiled eBPF object never crosses this path |

Security: authn=mTLS-client-cert-server-direction; authz=only-bundles-of-the-project-bound-to-the-fingerprint; integrity=TLS; code=never-sent; audit=configuration-changes-recorded-in-agent_audit

## event: KeyRotation

Server to the WAF agent only. The eBPF agent ignores it.

| Field | Type | Rules |
|---|---|---|
| `command_id` | string | Required. The agent replies with a `CommandAck` that carries the same id |
| key material | n/a | Never logged on any side |

Security: authn=mTLS-client-cert; authz=only-agents-of-the-project; confirmation=CommandAck-required; logging=key-material-never-logged

## event: CertificateInstall

Server to the WAF agent that serves the app. It carries an uploaded certificate chain and its private key. Defined since `shared/v0.2.0`; this control plane does not send it yet. The bundle names a certificate by `certificate_id` and `leaf_sha256` and never carries key material, because the agent stores the bundle in plain text (`last-bundle.json`).

| Field | Type | Rules |
|---|---|---|
| `command_id` | string | Required, random per delivery. The agent replies with a `CommandAck` that carries the same id; the server accepts the ack only from the stream it sent the install on |
| `app_id` | string | Required, canonical lower-case UUID. An app in the agent's latest applied bundle |
| `certificate_id` | string | Required, canonical lower-case UUID, the id the bundle names. An upload or a replace always gets a new id, so an id never names other bytes |
| `chain_pem` | bytes | Required. Only `CERTIFICATE` blocks, leaf first, at most 10 certificates and 64 KiB; any other block (a key in a combined file) is refused |
| `key_pem` | bytes | Required. One PKCS#8, PKCS#1 or SEC1 private key, PEM, no passphrase, at most 16 KiB. It must match the leaf. Marked `debug_redact` in the proto; Go's generated `String()` ignores that, so no side ever formats this message |
| `leaf_sha256` | string | Required. Lower-case hex SHA-256 of the DER of the leaf; must match `chain_pem` and the bundle |
| receiver | n/a | Only a stream whose `hello.features` holds `tls_certificates` and whose mTLS credential is host-bound (host-key enrollment) to this agent's host, kind `waf` and name. A project-wide credential never receives a key, since it can connect under any agent name. At send time the server reads the app's enabled `waf_agent_apps` row, joined on the project |
| when | n/a | After the `BundleUpdate` that names the certificate: after `Welcome` on connect, after an upload, a replace or a move of the app, and again when a `CertificateStatus` reports the app `missing` with a `certificate_id` the server holds. Every delivery is audited (credential, host, agent, app, certificate, peer address) |
| agent checks | n/a | The agent refuses an install that its latest applied bundle does not name (`app_id`, `certificate_id` and `leaf_sha256`), then checks the blocks, the sizes, the key against the leaf and `leaf_sha256` against the chain. It acks `ok=true` without a write when it already holds this `certificate_id` with this `leaf_sha256` |
| ack codes | n/a | `CommandAck.error` is one of `bad_pem`, `too_large`, `key_mismatch`, `leaf_mismatch`, `unsupported_key`, `not_in_bundle`, `write_failed`; never free text or parser output |
| agent storage | n/a | A fixed directory, `/var/lib/wafio-waf-agent/tls/` (directory 0700, files 0600, user `wafio`), that does not follow `--state-dir`; the host agent rates reads there as credential reads. Files are written to a temporary name inside that directory and renamed. A certificate is served only while the bundle names it, and its files are deleted once the bundle no longer does |
| recall | n/a | A key already sent to an agent that is offline, removed or no longer serves the app is not recalled. The dashboard advises replacing the certificate after a move or a removal |
| key material | n/a | Never logged on any side, never in a `CommandAck`, never in a `BundleUpdate`, in telemetry or in the bundle cache |

Security: authn=mTLS-client-cert-host-bound-only; authz=enabled-assignment-of-the-app-to-this-agent-in-this-project-at-send-time; confirmation=CommandAck-from-the-same-stream; logging=key-material-never-logged-message-never-formatted; storage=fixed-agent-key-directory-0600; audit=every-delivery

## event: CertificateStatus

WAF agent to the server, only from an agent with the `tls_certificates` feature, for each app whose bundle entry turns TLS on: once after each applied bundle, and again when the state or the certificate in use changes. Defined since `shared/v0.2.0`; this control plane ignores it so far. An older control plane never sends TLS settings in the bundle, so it never receives the message; if it did, it would skip it as an unknown kind.

| Field | Type | Rules |
|---|---|---|
| `app_id` | string | Required. The server drops the status unless the app has an enabled assignment to this stream's agent in this stream's project when it arrives |
| `source` | string | `acme` (the agent orders and renews) or `uploaded` (from `CertificateInstall`); dropped when it does not match the app's settings |
| `state` | string | `pending` (an ACME order is running), `active` (a certificate is in use), `failed` (the last order or install failed; `chain_pem` is set while an older certificate is still in use), `missing` (TLS is on, nothing to serve yet). Any other value is dropped |
| `certificate_id` | string | For `uploaded`, the id the bundle names, looked up by project, app and id together; empty for `acme` |
| `chain_pem` | bytes | The chain in use, leaf first; public material. Only `CERTIFICATE` blocks, at most 10 certificates and 64 KiB, or the status is dropped. The server parses it itself (issuer, names, expiry) and does not trust the agent's reading. It parses only when `leaf_sha256` differs from the stored one; otherwise it ignores `chain_pem` and stores nothing from it |
| `leaf_sha256` | string | Lower-case hex SHA-256 of the DER of the leaf; the server checks it against `chain_pem` |
| `error` | string | For `failed`, at most 1 KiB. Control characters are stripped, and the dashboard and email escape it; never key material |
| `next_attempt_unix` | int64 | For `pending` and `failed`, when the agent tries again; 0 when nothing is planned |
| `request_id` | string | The ACME request id of the bundle entry this state answers; a new id in the bundle asks the agent to order now. A status with any id other than the current one is dropped. Empty for `uploaded` |
| `unix_time` | int64 | When the agent saw this state. The server stores its own receive time |

Security: authn=mTLS-client-cert; authz=enabled-assignment-of-the-app-to-this-agent-in-this-project; input=untrusted-parsed-size-capped-and-escaped-by-the-server; key-material=never-carried

## Evolution rules

- Every change to the `.proto` is followed by `./scripts/gen-proto.sh`; the result in `shared/agentpb/` is committed.
- A field number must not be reused; mark it `reserved` like field 5 of `Hello`.
- `shared/agentpb/testdata/wire_fields.golden` records every field (number, name, kind, oneof) and every reserved number. Its test fails on a line that changed or went missing; after an intended addition, `go test ./agentpb -run TestWireFieldsKeepTheirNumbers -update` (from `shared/`) adds the new lines.
- A new field is optional by default in proto3; an old agent ignores it.
- Adding a third kind of agent does not need a new service: add a variant to the oneof and let the other kinds ignore it.

## rpc: DownloadMalwareDatabase

A server-streaming RPC for the global hash corpus. It uses the same mTLS interceptor as `Stream`; the certificate must be registered and active. The corpus is not project data and holds no Auth-Key, no user upload and no tenant rules. `MalwareDatabaseRequest` is empty; it accepts no path or URL from the agent.

| Field | Type | Rules |
|---|---|---|
| request | `MalwareDatabaseRequest` | Empty; requires an active mTLS credential |
| `data` | bytes | At most 64 KiB per chunk; at most 128 MiB in total |
| `sha256` | string | Final frame only; the digest matches all the data and is followed by EOF |

The server reads a snapshot of a file that it opened once, sends `data` chunks of at most 64 KiB, then one final `sha256` frame without data. The total is at most 128 MiB. The agent must receive a matching checksum and the end of the stream before it validates the SHA-256 records and replaces the file atomically. A failure keeps the old file. An agent transfer is limited to two minutes and one active transfer per process.

`FetchSecurityData.malware_from_control_plane` (field 4) points the `malware` component at this RPC instead of sending the provider credential. The WAF agent also synchronises when it reconnects and reports the `malware` component in `secdata:status`. Complete the upgrade of the control plane and the WAF agent for the central flow; an old agent ignores the new field and still needs the old fetch configuration. A finished update on the control plane is not proof that all agents have finished applying it.

Security: authn=mTLS-client-cert; authz=active-credential; tenancy=global-corpus-without-tenant-data; transport=TLS-required; audit=admin.security_data_updated
