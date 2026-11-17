# Wafio lab upstream

A deliberately inert HTTP service for testing WAF routing and decisions. It never executes request input, writes uploaded files, performs arbitrary outbound requests, or exposes a real login. Responses render submitted content as JSON. The only fixture credentials are `lab` / `wafio-lab-only`; they grant no privileges.

```sh
go test ./test/lab-upstream
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/wafio-lab-linux ./test/lab-upstream
```

The default upstream binds Linux loopback `127.0.0.1:18087`. Place the WAF in front on the VPN address `10.1.1.1:18088`; configure that route through the agent's route API/UI. The upstream remains inaccessible directly from the Mac. `X-Request-ID` is preserved when valid and is logged with method/path, without body/query secrets. `X-Wafio-Lab-Reached: true` distinguishes a request that reached this service from a WAF rejection.

| Endpoint | Fixture behavior |
|---|---|
| `GET /health` | JSON health response |
| `GET /search?q=` | Inert JSON search input |
| `POST /api/echo`, `/notes`, `/upload` | JSON-escaped body and byte count; 1 MiB limit |
| `POST /login` | Dummy JSON username/password, success or 401 |
| `GET /redirect?to=` | Only `/` or `/health` accepted |
| `GET /slow?ms=` | Cancellable delay, bounded to 2 seconds |
| `GET /status/{code}` | Explicit 400–599 response fixture |

Run the bounded smoke check only against this configured lab:

```sh
python3 test/lab-upstream/smoke.py --base-url http://10.1.1.1:18088 --output build/lab/waf-smoke.json
```

The four cases assert allow/block and upstream reachability. They are not a complete detection evaluation. Durations include network round-trip and must not be reported as WAF processing p99. Broader engine evaluation lives in the WAF corpus tests. Correlate decisions with the same request IDs and time window in the control plane.

Bounded synthetic traffic acceptance:

```sh
python3 test/lab-upstream/load.py --benign-only --output build/lab/benign-load.json
```

Runs 20 seconds each at 10, 25 and 50 requests/second, with ten workers and a three-second request timeout. Stops on unexpected response/reachability, RTT above two seconds, or 20 outstanding requests. The benign mode uses five explicitly synthetic user-agent cohorts; this keeps each below the existing 500/minute flood policy without altering configuration. Fixtures include a 50ms upstream delay and an intentional upstream 503. Omitting `--benign-only` includes SQL/XSS fixtures with one client identity: accumulated attack blocks can intentionally trigger temporary block policy and stop the run. Report that result separately from detector false positives. All reported timings here are network RTT; correlate request IDs with agent `latency_us` for preproxy decision timings.

After lower-rate acceptance and a resource check, `--benign-only --high-rate` selects 100 then 250 RPS for 20 seconds each, 32 workers, 20 synthetic cohorts and a 64-outstanding stop bound. Each cohort remains below 500 requests/minute. It is opt-in and should not run alongside other lab load. Higher rates are an acceptance experiment, not a claimed supported capacity.

The loader uses a direct HTTP opener for this fixed private listener, ignoring ambient proxy environment settings. Running it on the Linux lab measures a local connection to its VPN-address listener, without traversing the VPN tunnel; the artifact records the client platform. Such a run shares CPU with the agent and must be reported separately from Mac-to-Linux VPN traffic.
