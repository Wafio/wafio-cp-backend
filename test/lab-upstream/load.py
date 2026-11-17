#!/usr/bin/env python3
"""Bounded, paced synthetic acceptance traffic for the isolated inert WAF lab."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import http.client
import threading
import math
from pathlib import Path
import platform
import time
import urllib.error
import urllib.parse
import urllib.request


class PersistentClient:
    def __init__(self, host='10.1.1.1', port=18088):
        self.host, self.port = host, port
        self.local = threading.local()
        self.connections = []
        self.lock = threading.Lock()

    def open(self, request):
        if not hasattr(self.local, 'connection'):
            self.local.connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
            with self.lock:
                self.connections.append(self.local.connection)
        connection = self.local.connection
        try:
            connection.request(request.get_method(), request.selector, request.data, dict(request.header_items()))
            return connection.getresponse()
        except (OSError, http.client.HTTPException):
            connection.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        for connection in self.connections:
            connection.close()


def wait_until(scheduled):
    delay = scheduled - time.perf_counter()
    if delay > 0:
        time.sleep(delay)


def client_timing(scheduled, submitted, worker_started):
    return {
        'dispatch_lag_ms': round((submitted - scheduled) * 1000, 3),
        'client_queue_ms': round((worker_started - submitted) * 1000, 3),
    }


def collect_completed(pending, results):
    completed = {future for future in pending if future.done()}
    failure = None
    for future in completed:
        result = future.result()
        results.append(result)
        if not result['passed'] or result['round_trip_ms'] > 2000:
            failure = 'unexpected response or RTT above 2 seconds'
    pending.difference_update(completed)
    return failure


def cohort_count(rate):
    # Stay below the lab's existing 500/minute per-identity flood policy even on long runs.
    return max(5, math.ceil(rate * 60 / 400))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--high-rate', action='store_true', help='100 then 250 RPS; benign-only, 20 synthetic cohorts, 32 workers')
    parser.add_argument('--benign-only', action='store_true', help='five synthetic user-agent cohorts, no attack fixtures')
    parser.add_argument('--keep-alive', action='store_true', help='reuse one HTTP connection per client worker; default opens a new connection per request')
    parser.add_argument('--duration', type=int, default=20, help='seconds per stage, 1–1800')
    parser.add_argument('--rates', help='comma-separated target RPS, each 1–1000')
    parser.add_argument('--workers', type=int, help='concurrent clients, 1–128')
    args = parser.parse_args(argv)
    if not 1 <= args.duration <= 1800:
        parser.error('--duration must be 1–1800')
    if args.workers is not None and not 1 <= args.workers <= 128:
        parser.error('--workers must be 1–128')
    try:
        args.rates = tuple(int(rate) for rate in args.rates.split(',')) if args.rates else None
    except ValueError:
        parser.error('--rates requires integers')
    if args.rates and (len(args.rates) > 10 or any(not 1 <= rate <= 1000 for rate in args.rates)):
        parser.error('--rates requires 1–10 rates within 1–1000')
    if args.high_rate and not args.benign_only:
        parser.error("--high-rate requires --benign-only")
    if (args.rates or args.duration != 20) and not args.benign_only:
        parser.error('custom workload requires --benign-only')
    return args


def main():
    args = parse_args()
    workers = args.workers or (32 if args.high_rate else 10)
    max_pending = workers * 2
    rates = args.rates or ((100, 250) if args.high_rate else (10, 25, 50))
    cohorts = cohort_count(max(rates))
    cases = [
        ('health', '/health', None, 200, True),
        ('search', '/search?q=' + urllib.parse.quote("O'Reilly quarterly report"), None, 200, True),
        ('json', '/api/echo', b'{"note":"Revenue increased 12 percent"}', 200, True),
        ('slow', '/slow?ms=50', None, 200, True),
        ('upstream-error', '/status/503', None, 503, True),
        ('sql', '/search?q=' + urllib.parse.quote("1' UNION SELECT username,password FROM users--"), None, 403, False),
        ('xss', '/api/echo', b'<script>alert(document.cookie)</script>', 403, False),
        ('health-2', '/health', None, 200, True),
    ]
    if args.benign_only:
        cases = [case for case in cases if case[4]]
    run_epoch, run_clock = time.time(), time.perf_counter()
    run_id = str(time.time_ns())
    results, stages = [], []
    # The dedicated VPN-address listener must not traverse ambient HTTP proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(index, rate, scheduled, submitted):
        worker_started = time.perf_counter()
        name, path, body, status, reached = cases[index % len(cases)]
        identity = f'lab-load-{run_id}-{index}'
        req = urllib.request.Request('http://10.1.1.1:18088' + path, data=body,
            headers={'X-Request-ID': identity, 'User-Agent': f'WafioLabBenign/{run_id}/{index % cohorts}' if args.benign_only else 'WafioLab/1.0',
                     'Content-Type': 'application/json' if name == 'json' else 'text/plain'})
        started = time.perf_counter()
        result = {'case': name, 'request_id': identity, 'rate': rate,
                  'scheduled_unix': run_epoch + scheduled - run_clock,
                  **client_timing(scheduled, submitted, worker_started)}
        try:
            try:
                response = persistent.open(req) if args.keep_alive else opener.open(req, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                response.read(1 << 20)
                actual_reached = response.headers.get('X-Wafio-Lab-Reached') == 'true'
                result.update(status=response.status, upstream_reached=actual_reached,
                              passed=response.status == status and actual_reached == reached)
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            result.update(passed=False, error=type(error).__name__)
        result['round_trip_ms'] = round((time.perf_counter() - started) * 1000, 3)
        return result

    stopped = None
    with PersistentClient() as persistent, ThreadPoolExecutor(max_workers=workers) as pool:
        for rate in rates:
            started = time.perf_counter()
            pending = set()
            stage_start = len(results)
            for index in range(rate * args.duration):
                scheduled = started + index / rate
                wait_until(scheduled)
                stopped = collect_completed(pending, results)
                if stopped:
                    break
                if len(pending) >= max_pending:
                    stopped = f'{max_pending} outstanding requests'
                    break
                pending.add(pool.submit(request, stage_start + index, rate, scheduled, time.perf_counter()))
            for future in pending:
                results.append(future.result())
            stage = results[stage_start:]
            timings = sorted(item['round_trip_ms'] for item in stage)
            stages.append({'target_rps': rate, 'requests': len(stage), 'elapsed_seconds': time.perf_counter()-started,
                'passed': sum(item['passed'] for item in stage),
                'status_counts': dict(Counter(str(item.get('status', 'error')) for item in stage)),
                **{f'p{p}_round_trip_ms': timings[math.ceil(len(timings)*p/100)-1] for p in (50, 95, 99)},
                'max_round_trip_ms': max(timings),
                'max_dispatch_lag_ms': max(item['dispatch_lag_ms'] for item in stage),
                'max_client_queue_ms': max(item['client_queue_ms'] for item in stage)})
            print(json.dumps(stages[-1]), flush=True)
            if stopped or any(not item['passed'] or item['round_trip_ms'] > 2000 for item in stage):
                stopped = stopped or 'unexpected response or RTT above 2 seconds'
                break
    report = {'run_id': run_id, 'scope': 'HTTP round-trip to the VPN-address listener including upstream delay; not inline Analyze latency', 'client_platform': platform.platform(),
              'workers': workers, 'connection_mode': 'keep-alive' if args.keep_alive else 'new-per-request', 'duration_seconds': args.duration, 'max_pending': max_pending, 'benign_only': args.benign_only, 'synthetic_user_agent_cohorts': cohorts if args.benign_only else 1, 'stopped': stopped, 'stages': stages, 'requests': results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    return 1 if stopped else 0


if __name__ == '__main__':
    raise SystemExit(main())
