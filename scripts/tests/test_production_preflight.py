import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "production_preflight.py"


class ProductionPreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self._command("pg_isready", "exit 0")
        self._command("psql", "printf '72|f\\n'")
        self.config = self.root / "config.yaml"
        self.config.write_text("server:\n  http_addr: 127.0.0.1:9087\n")
        self.config.chmod(0o640)
        self.frontend = self.root / "frontend"
        self.frontend.mkdir()
        (self.frontend / "index.html").write_text("ready")
        self.version = "v9.8.7"
        self.public_key, private_key, private_seed = self._ed25519_keypair()
        self.private_key = private_key
        self.signing_key = self.root / "release.key"
        self.signing_key.write_bytes(base64.b64encode(private_seed + base64.b64decode(self.public_key)) + b"\n")
        self.signing_key.chmod(0o600)
        self.secret_marker = self.signing_key.read_text().strip()
        self.artifacts = []
        for name in ("wafio-controlplane", "wafio-waf-agent", "wafio-host-agent"):
            artifact = self.root / f"{name}-{self.version}-linux-amd64.tar.gz"
            artifact.write_bytes(name.encode())
            self._sign(artifact)
            self.artifacts.append(artifact)

    def _command(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _ed25519_keypair(self):
        private = self.root / "verify-private.pem"
        private_der = self.root / "verify-private.der"
        public_der = self.root / "verify-public.der"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run([
            "openssl", "pkey", "-in", str(private), "-outform", "DER", "-out", str(private_der),
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER", "-out", str(public_der),
        ], check=True, capture_output=True)
        raw_public = public_der.read_bytes()
        raw_private = private_der.read_bytes()
        self.assertEqual(raw_public[:12].hex(), "302a300506032b6570032100")
        self.assertEqual(raw_private[:16].hex(), "302e020100300506032b657004220420")
        return base64.b64encode(raw_public[12:]).decode(), private, raw_private[16:]

    def _sign(self, artifact):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        payload = self.root / "artifact.payload"
        raw_signature = self.root / "artifact.rawsig"
        payload.write_bytes(f"wafio-release-v1\n{self.version}\n{digest}".encode())
        subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key),
            "-rawin", "-in", str(payload), "-out", str(raw_signature),
        ], check=True, capture_output=True)
        Path(str(artifact) + ".sig").write_bytes(base64.b64encode(raw_signature.read_bytes()) + b"\n")

    def _run(self, *extra):
        args = [
            sys.executable, str(SCRIPT), "--config", str(self.config),
            "--frontend", str(self.frontend), "--database-service", "fixture",
            "--expected-schema", "72", "--release-version", self.version,
            "--release-public-key", self.public_key, "--signing-key-file", str(self.signing_key),
        ]
        for artifact in self.artifacts:
            args.extend(("--artifact", str(artifact)))
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env["PATH"]
        return subprocess.run(args + list(extra), text=True, capture_output=True, env=env)

    def test_complete_fixture_passes_without_modifying_inputs(self):
        before = {path: path.stat().st_mtime_ns for path in [self.config, self.signing_key, *self.artifacts]}
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(all(check["status"] == "pass" for check in report["checks"]))
        self.assertEqual(before, {path: path.stat().st_mtime_ns for path in before})

    def test_failures_are_aggregated_and_secrets_are_not_printed(self):
        self.signing_key.chmod(0o644)
        self.artifacts[0].with_suffix(self.artifacts[0].suffix + ".sig").write_text("invalid")
        (self.frontend / "index.html").unlink()
        self._command("pg_isready", "exit 1")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        failed = {check["name"] for check in report["checks"] if check["status"] == "fail"}
        self.assertTrue({"frontend", "database", "signing_key", "release_artifacts"}.issubset(failed))
        self.assertNotIn(self.secret_marker, result.stdout + result.stderr)

    def test_dirty_or_incompatible_schema_fails_closed(self):
        self._command("psql", "printf '71|t\\n'")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "schema")
        self.assertEqual(check["status"], "fail")
        self.assertNotIn("71|t", check["detail"])

    def test_signing_key_must_match_compiled_release_public_key(self):
        self.signing_key.write_bytes(base64.b64encode(b"x" * 64) + b"\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "signing_key")
        self.assertEqual(check["status"], "fail")

    def test_corrupted_seed_is_rejected_even_when_stored_public_half_matches(self):
        stored = base64.b64decode(self.signing_key.read_text())
        corrupted_seed = bytes([stored[0] ^ 1]) + stored[1:32]
        self.signing_key.write_bytes(base64.b64encode(corrupted_seed + stored[32:]) + b"\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "signing_key")
        self.assertEqual(check["status"], "fail")

    def test_corrupted_stored_public_half_is_rejected_even_when_seed_is_valid(self):
        stored = base64.b64decode(self.signing_key.read_text())
        corrupted_public = bytes([stored[32] ^ 1]) + stored[33:]
        self.signing_key.write_bytes(base64.b64encode(stored[:32] + corrupted_public) + b"\n")
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "signing_key")
        self.assertEqual(check["status"], "fail")

    def test_one_collision_filename_cannot_satisfy_three_components(self):
        collision = self.root / f"wafio-controlplane-waf-agent-host-agent-{self.version}-linux-amd64.tar.gz"
        self.artifacts[0].replace(collision)
        Path(str(self.artifacts[0]) + ".sig").replace(Path(str(collision) + ".sig"))
        self.artifacts = [collision]
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "release_artifacts")
        self.assertEqual(check["status"], "fail")

    def test_empty_bundle_is_rejected_even_with_valid_signature(self):
        self.artifacts[0].write_bytes(b"")
        self._sign(self.artifacts[0])
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "release_artifacts")
        self.assertEqual(check["status"], "fail")

    def test_all_three_component_artifacts_are_required(self):
        missing = self.artifacts.pop()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        check = next(item for item in json.loads(result.stdout)["checks"] if item["name"] == "release_artifacts")
        self.assertEqual(check["status"], "fail")
        self.assertIn("host-agent", check["detail"])


if __name__ == "__main__":
    unittest.main()
