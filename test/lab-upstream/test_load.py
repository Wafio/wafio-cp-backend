import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('lab_load', Path(__file__).with_name('load.py'))
load = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load)

class LoadTests(unittest.TestCase):
    def test_completed_batch_is_examined_once(self):
        class Future:
            calls = 0
            def done(self): return True
            def result(self):
                self.calls += 1
                return {'passed': True, 'round_trip_ms': 1}
        future = Future()
        pending, results = {future}, []
        self.assertIsNone(load.collect_completed(pending, results))
        self.assertIsNone(load.collect_completed(pending, results))
        self.assertEqual(future.calls, 1)
        self.assertEqual(len(results), 1)
        self.assertFalse(pending)

    def test_failed_response_and_excessive_latency_stop(self):
        from concurrent.futures import Future
        for result in ({'passed': False, 'round_trip_ms': 1}, {'passed': True, 'round_trip_ms': 2001}):
            future = Future(); future.set_result(result)
            self.assertIsNotNone(load.collect_completed({future}, []))

    def test_long_runs_keep_each_synthetic_identity_below_policy(self):
        self.assertGreaterEqual(load.cohort_count(250), 38)
        self.assertGreaterEqual(load.cohort_count(50), 8)
        self.assertLessEqual(250 * 60 / load.cohort_count(250), 400)

    def test_pacing_sleeps_only_until_scheduled_time(self):
        from unittest.mock import patch
        with patch.object(load.time, 'perf_counter', return_value=10), patch.object(load.time, 'sleep') as sleep:
            load.wait_until(10.25)
            sleep.assert_called_once_with(.25)
            sleep.reset_mock()
            load.wait_until(9.5)
            sleep.assert_not_called()

    def test_dispatch_and_worker_queue_are_distinct(self):
        self.assertEqual(load.client_timing(10, 10.02, 10.17),
                         {'dispatch_lag_ms': 20, 'client_queue_ms': 150})

    def test_failure_arriving_at_final_drain_is_not_lost(self):
        from concurrent.futures import Future
        future = Future(); pending = {future}; results = []
        self.assertIsNone(load.collect_completed(pending, results))
        future.set_result({'passed':False, 'round_trip_ms':10})
        self.assertIsNotNone(load.collect_completed(pending, results))
        self.assertFalse(pending)
        self.assertFalse(results[0]['passed'])

    def test_keep_alive_reuses_connection_and_preserves_response(self):
        import http.server
        import threading
        import urllib.request
        ports = []
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_GET(self):
                ports.append(self.client_address[1])
                self.send_response(503)
                self.send_header('Content-Length', '2')
                self.send_header('X-Wafio-Lab-Reached', 'true')
                self.end_headers()
                self.wfile.write(b'ok')
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with load.PersistentClient(*server.server_address) as client:
                for _ in range(2):
                    request = urllib.request.Request('http://127.0.0.1:%d/health' % server.server_port)
                    with client.open(request) as response:
                        self.assertEqual(response.status, 503)
                        self.assertEqual(response.read(), b'ok')
                        self.assertEqual(response.headers['X-Wafio-Lab-Reached'], 'true')
            self.assertEqual(len(ports), 2)
            self.assertEqual(ports[0], ports[1])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_bounds_reject_invalid_workload(self):
        for argv in (['--duration', '0'], ['--duration','1801'], ['--workers','0'], ['--rates','0'], ['--rates','1001']):
            with self.assertRaises(SystemExit):
                load.parse_args(['--output','/tmp/not-created', *argv])

if __name__ == '__main__': unittest.main()
