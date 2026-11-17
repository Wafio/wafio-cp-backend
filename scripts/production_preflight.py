#!/usr/bin/env python3
"""Read-only production release acceptance checks."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


COMPONENTS = ("controlplane", "waf-agent", "host-agent")
PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
PRIVATE_SEED_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def result(name, ok, detail):
    return {"name": name, "status": "pass" if ok else "fail", "detail": detail}


def run(command, *, env=None):
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_dependencies():
    missing = [name for name in ("openssl", "pg_isready", "psql") if not shutil.which(name)]
    return result("dependencies", not missing, "required commands available" if not missing else "missing: " + ", ".join(missing))


def check_file(name, path, description):
    ok = path.is_file() and os.access(path, os.R_OK) and path.stat().st_size > 0
    return result(name, ok, f"{description} present" if ok else f"{description} missing, empty, or unreadable")


def check_signing_key(path, encoded_public_key):
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        raw = base64.b64decode(path.read_text().strip(), validate=True)
        public_key = base64.b64decode(encoded_public_key.strip(), validate=True)
        if not path.is_file() or len(raw) != 64 or len(public_key) != 32 or mode & 0o077:
            raise ValueError
        with tempfile.TemporaryDirectory(prefix="wafio-key-check-") as directory:
            private_der = Path(directory) / "private.der"
            derived_der = Path(directory) / "public.der"
            private_der.write_bytes(PRIVATE_SEED_DER_PREFIX + raw[:32])
            private_der.chmod(0o600)
            derived = run([
                "openssl", "pkey", "-inform", "DER", "-in", str(private_der),
                "-pubout", "-outform", "DER", "-out", str(derived_der),
            ])
            ok = (
                raw[32:] == public_key
                and derived is not None
                and derived.returncode == 0
                and derived_der.read_bytes() == PUBLIC_KEY_DER_PREFIX + public_key
            )
    except (OSError, ValueError):
        ok = False
    return result("signing_key", ok, "protected Ed25519 signing material available" if ok else "signing key missing, malformed, or accessible outside its owner")


def check_database(service):
    env = os.environ.copy()
    env["PGSERVICE"] = service
    ready = run(["pg_isready", "--quiet"], env=env)
    return result("database", ready is not None and ready.returncode == 0, "PostgreSQL service is accepting connections" if ready is not None and ready.returncode == 0 else "PostgreSQL service is unavailable")


def check_schema(service, expected):
    env = os.environ.copy()
    env["PGSERVICE"] = service
    query = run(["psql", "-XAt", "-c", "SELECT version, dirty FROM schema_migrations"], env=env)
    ok = query is not None and query.returncode == 0 and query.stdout.strip() == f"{expected}|f"
    return result("schema", ok, f"schema {expected} is current and clean" if ok else f"schema is unavailable, dirty, or differs from required version {expected}")


def decode_public_key(encoded):
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def verify_artifact(artifact, version, public_key, workspace):
    signature_path = Path(str(artifact) + ".sig")
    try:
        signature = base64.b64decode(signature_path.read_text().strip(), validate=True)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    except (OSError, ValueError):
        return False
    if len(signature) != 64:
        return False
    key_path = workspace / "public.der"
    payload_path = workspace / "payload"
    signature_raw = workspace / "signature"
    key_path.write_bytes(PUBLIC_KEY_DER_PREFIX + public_key)
    payload_path.write_bytes(f"wafio-release-v1\n{version}\n{digest}".encode())
    signature_raw.write_bytes(signature)
    verified = run([
        "openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
        "-inkey", str(key_path), "-rawin", "-in", str(payload_path),
        "-sigfile", str(signature_raw),
    ])
    return verified is not None and verified.returncode == 0


def check_artifacts(artifacts, version, encoded_public_key):
    expected_names = {f"wafio-{component}-{version}-linux-amd64.tar.gz" for component in COMPONENTS}
    supplied_names = {path.name for path in artifacts}
    missing_components = sorted(expected_names - supplied_names)
    unexpected = sorted(supplied_names - expected_names)
    public_key = decode_public_key(encoded_public_key)
    invalid = []
    if public_key is not None:
        with tempfile.TemporaryDirectory(prefix="wafio-preflight-") as directory:
            workspace = Path(directory)
            for index, artifact in enumerate(artifacts):
                item_workspace = workspace / str(index)
                item_workspace.mkdir()
                if (
                    not artifact.is_file()
                    or artifact.stat().st_size == 0
                    or not os.access(artifact, os.R_OK)
                    or not verify_artifact(artifact, version, public_key, item_workspace)
                ):
                    invalid.append(artifact.name)
    else:
        invalid.append("release public key")
    ok = len(artifacts) == len(COMPONENTS) and not missing_components and not unexpected and not invalid
    problems = []
    if missing_components:
        problems.append("missing artifacts: " + ", ".join(missing_components))
    if unexpected:
        problems.append("unexpected artifacts: " + ", ".join(unexpected))
    if invalid:
        problems.append("missing or invalid signatures: " + ", ".join(invalid))
    return result("release_artifacts", ok, "all component artifacts have valid version-bound signatures" if ok else "; ".join(problems))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--frontend", required=True, type=Path)
    parser.add_argument("--database-service", required=True)
    parser.add_argument("--expected-schema", required=True, type=int)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--release-public-key", required=True)
    parser.add_argument("--signing-key-file", required=True, type=Path)
    parser.add_argument("--artifact", required=True, action="append", type=Path)
    return parser.parse_args()


def main():
    args = parse_args()
    checks = [
        check_dependencies(),
        check_file("config", args.config, "production configuration"),
        check_file("frontend", args.frontend / "index.html", "production frontend index"),
        check_database(args.database_service),
        check_schema(args.database_service, args.expected_schema),
        check_signing_key(args.signing_key_file, args.release_public_key),
        check_artifacts(args.artifact, args.release_version, args.release_public_key),
    ]
    passed = all(item["status"] == "pass" for item in checks)
    print(json.dumps({"status": "pass" if passed else "fail", "checks": checks}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
