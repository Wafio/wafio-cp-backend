#!/usr/bin/env python3
"""Bounded WAF smoke checks for the dedicated VPN lab only."""
import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://10.1.1.1:18088")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = urllib.parse.urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in ("10.1.1.1", "127.0.0.1", "localhost") or target.port != 18088 or target.username or target.password or target.query or target.fragment or target.path not in ("", "/"):
        parser.error("target must be the isolated lab on VPN/loopback port 18088")
    cases = [
        ("health", "/health", None, 200, True),
        ("search_benign", "/search?q=" + urllib.parse.quote("quarterly report 2026"), None, 200, True),
        ("sql_attack", "/search?q=" + urllib.parse.quote("1' UNION SELECT username,password FROM users--"), None, 403, False),
        ("xss_attack", "/api/echo", b"<script>alert(document.cookie)</script>", 403, False),
    ]
    results = []
    run_id = str(time.time_ns())
    for name, path, body, expected_status, expected_upstream in cases:
        request_id = f"lab-{run_id}-{name}"
        request = urllib.request.Request(args.base_url.rstrip("/") + path, data=body, headers={"X-Request-ID": request_id, "User-Agent": "WafioLab/1.0", "Content-Type": "text/plain"})
        start = time.perf_counter()
        try:
            try:
                response = urllib.request.urlopen(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                response.read(1 << 20)
                reached = response.headers.get("X-Wafio-Lab-Reached") == "true"
                results.append({"case": name, "request_id": request_id, "status": response.status, "upstream_reached": reached, "passed": response.status == expected_status and reached == expected_upstream, "round_trip_ms": round((time.perf_counter() - start) * 1000, 3)})
        except (OSError, urllib.error.URLError):
            results.append({"case": name, "request_id": request_id, "passed": False, "error": "request failed"})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(f"{sum(r['passed'] for r in results)}/{len(results)} lab smoke cases passed; evidence: {args.output}")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
