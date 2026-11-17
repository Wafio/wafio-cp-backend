#!/usr/bin/env python3
"""Create and restore encrypted WAFio control-plane backups."""

from __future__ import annotations

import argparse
import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


os.umask(0o077)
FORMAT_VERSION = 1
Run = Callable[..., subprocess.CompletedProcess]


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupConfig:
    database_url_file: pathlib.Path
    destination_directory: pathlib.Path
    gpg_recipient: str
    include_paths: tuple[pathlib.Path, ...] = ()
    gpg_homedir: pathlib.Path | None = None
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_key_prefix: str = ""
    aws_region: str = "us-east-1"
    aws_profile: str | None = None
    aws_config_file: pathlib.Path | None = None
    retention_count: int | None = None
    pg_dump: str = "pg_dump"
    pg_restore: str = "pg_restore"
    psql: str = "psql"
    gpg: str = "gpg"
    aws: str = "aws"


def _require_private_file(path: pathlib.Path, label: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError as exc:
        raise BackupError(f"{label} does not exist") from exc
    if not path.is_file():
        raise BackupError(f"{label} must be a regular file")
    if mode & 0o077:
        raise BackupError(f"{label} permissions must deny group and other access")


def _require_private_directory(path: pathlib.Path, label: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError as exc:
        raise BackupError(f"{label} does not exist") from exc
    if not path.is_dir():
        raise BackupError(f"{label} must be a directory")
    if mode & 0o077:
        raise BackupError(f"{label} permissions must deny group and other access")


def load_config(path: pathlib.Path) -> BackupConfig:
    _require_private_file(path, "configuration")
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("configuration is not valid JSON") from exc
    required = ("database_url_file", "destination_directory", "gpg_recipient")
    missing = [key for key in required if not raw.get(key)]
    if missing:
        raise BackupError(f"missing configuration: {', '.join(missing)}")
    if not str(raw["gpg_recipient"]).strip():
        raise BackupError("gpg_recipient must not be empty")

    database_url_file = pathlib.Path(raw["database_url_file"])
    destination = pathlib.Path(raw["destination_directory"])
    _require_private_file(database_url_file, "database URL file")
    _require_private_directory(destination, "destination directory")
    include_paths = tuple(pathlib.Path(value) for value in raw.get("include_paths", []))
    for include in include_paths:
        if not include.exists():
            raise BackupError(f"include path does not exist: {include}")
    retention = raw.get("retention_count")
    if retention is not None and (not isinstance(retention, int) or retention < 1):
        raise BackupError("retention_count must be a positive integer")
    s3 = raw.get("s3")
    if s3 is not None and not isinstance(s3, dict):
        raise BackupError("s3 must be an object")
    s3 = s3 or {}
    if s3 and (not s3.get("endpoint_url") or not s3.get("bucket")):
        raise BackupError("s3 endpoint_url and bucket are required together")
    endpoint = str(s3.get("endpoint_url", "")).strip()
    if endpoint and urllib.parse.urlparse(endpoint).scheme not in ("http", "https"):
        raise BackupError("s3 endpoint_url must be an HTTP(S) URL")
    aws_config_file = pathlib.Path(s3["aws_config_file"]) if s3.get("aws_config_file") else None
    if aws_config_file:
        _require_private_file(aws_config_file, "AWS settings file")
    gpg_homedir = pathlib.Path(raw["gpg_homedir"]) if raw.get("gpg_homedir") else None
    if gpg_homedir:
        _require_private_directory(gpg_homedir, "GnuPG home")
    binaries = raw.get("binaries", {})
    if not isinstance(binaries, dict):
        raise BackupError("binaries must be an object")
    return BackupConfig(
        database_url_file=database_url_file,
        destination_directory=destination,
        gpg_recipient=str(raw["gpg_recipient"]).strip(),
        include_paths=include_paths,
        gpg_homedir=gpg_homedir,
        s3_endpoint_url=endpoint or None,
        s3_bucket=str(s3["bucket"]) if s3.get("bucket") else None,
        s3_key_prefix=str(s3.get("key_prefix", "")).strip("/"),
        aws_region=str(s3.get("region") or "us-east-1"),
        aws_profile=str(s3["profile"]) if s3.get("profile") else None,
        aws_config_file=aws_config_file,
        retention_count=retention,
        pg_dump=str(binaries.get("pg_dump", "pg_dump")),
        pg_restore=str(binaries.get("pg_restore", "pg_restore")),
        psql=str(binaries.get("psql", "psql")),
        gpg=str(binaries.get("gpg", "gpg")),
        aws=str(binaries.get("aws", "aws")),
    )


def postgres_environment(database_url_file: pathlib.Path) -> dict[str, str]:
    value = database_url_file.read_text().strip()
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname or not parsed.path.strip("/"):
        raise BackupError("database URL file must contain a complete PostgreSQL URL")
    if parsed.username is None:
        raise BackupError("database URL must include a user")
    env = os.environ.copy()
    for name in (
        "PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR", "PGSSLMODE",
        "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGCONNECT_TIMEOUT",
    ):
        env.pop(name, None)
    env.update(
        PGHOST=parsed.hostname,
        PGPORT=str(parsed.port or 5432),
        PGUSER=urllib.parse.unquote(parsed.username),
        PGDATABASE=urllib.parse.unquote(parsed.path.lstrip("/")),
    )
    if parsed.password is not None:
        env["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    supported = {
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert": "PGSSLCERT",
        "sslkey": "PGSSLKEY",
        "connect_timeout": "PGCONNECT_TIMEOUT",
    }
    seen = set()
    for key, value in query_items:
        if key not in supported:
            raise BackupError(f"unsupported database URL query parameter: {key}")
        if key in seen or not value:
            raise BackupError(f"invalid repeated or empty database URL query parameter: {key}")
        seen.add(key)
        env[supported[key]] = value
    return env


def pg_dump_command(config: BackupConfig, output: pathlib.Path | None = None) -> list[str]:
    command = [config.pg_dump, "--format=custom", "--no-password"]
    if output is not None:
        command.extend(("--file", str(output)))
    return command


def artifact_basename() -> str:
    now = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"wafio-controlplane-{now}"


def _reject_symlinks(path: pathlib.Path) -> None:
    candidates = (path,) if not path.is_dir() else (path, *path.rglob("*"))
    for candidate in candidates:
        if candidate.is_symlink():
            raise BackupError(f"include path contains a symbolic link: {candidate}")


def _add_include(archive: tarfile.TarFile, path: pathlib.Path) -> None:
    _reject_symlinks(path)
    resolved = path.resolve()
    anchor = resolved.anchor
    relative = resolved.relative_to(anchor) if anchor else resolved
    archive.add(resolved, arcname=str(pathlib.PurePosixPath("files", *relative.parts)), recursive=True)


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_checked(run: Run, command: Sequence[str], label: str, **kwargs) -> None:
    try:
        run(list(command), check=True, **kwargs)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BackupError(f"{label} failed") from exc


def _gpg_base(config: BackupConfig) -> list[str]:
    command = [config.gpg, "--batch", "--yes"]
    if config.gpg_homedir:
        command.extend(("--homedir", str(config.gpg_homedir)))
    return command


def _aws_base(config: BackupConfig) -> list[str]:
    command = [config.aws, "--no-cli-pager", "--output", "json"]
    if config.aws_profile:
        command.extend(("--profile", config.aws_profile))
    command.extend(("--region", config.aws_region))
    if config.s3_endpoint_url:
        command.extend(("--endpoint-url", config.s3_endpoint_url))
    return command


def _aws_environment(config: BackupConfig) -> dict[str, str]:
    env = os.environ.copy()
    if config.aws_config_file:
        env["AWS_CONFIG_FILE"] = str(config.aws_config_file)
    return env


def _s3_key(config: BackupConfig, filename: str) -> str:
    return f"{config.s3_key_prefix}/{filename}" if config.s3_key_prefix else filename


def _upload_s3(config: BackupConfig, paths: Sequence[pathlib.Path], run: Run) -> None:
    assert config.s3_bucket
    env = _aws_environment(config)
    with tempfile.TemporaryDirectory(prefix="wafio-s3-verify-") as temp_name:
        temp = pathlib.Path(temp_name)
        for path in paths:
            digest = _sha256(path)
            checksum = base64.b64encode(bytes.fromhex(digest)).decode()
            key = _s3_key(config, path.name)
            put = [
                *_aws_base(config), "s3api", "put-object",
                "--bucket", config.s3_bucket, "--key", key,
                "--body", str(path), "--if-none-match", "*",
                "--checksum-sha256", checksum,
                "--metadata", f"sha256={digest}",
            ]
            _run_checked(run, put, "S3 upload", env=env, capture_output=True, text=True)
            downloaded = temp / path.name
            get = [
                *_aws_base(config), "s3api", "get-object",
                "--bucket", config.s3_bucket, "--key", key, str(downloaded),
            ]
            _run_checked(run, get, "S3 verification download", env=env, capture_output=True, text=True)
            if not downloaded.is_file() or downloaded.stat().st_size != path.stat().st_size or _sha256(downloaded) != digest:
                raise BackupError("S3 verification checksum failed")


def _prune(config: BackupConfig) -> None:
    if config.retention_count is None:
        return
    complete = []
    for manifest in config.destination_directory.glob("wafio-controlplane-*.manifest.json"):
        artifact = manifest.with_name(manifest.name.removesuffix(".manifest.json") + ".tar.gpg")
        try:
            _read_manifest(artifact, manifest)
        except BackupError:
            continue
        complete.append((manifest, artifact))
    for manifest, artifact in sorted(complete, reverse=True)[config.retention_count :]:
        artifact.unlink()
        manifest.unlink()


def _publish_exclusive(source: pathlib.Path, destination: pathlib.Path) -> None:
    try:
        os.link(source, destination)
    except FileExistsError as exc:
        raise BackupError("backup destination already exists") from exc
    source.unlink()


def create_backup(config: BackupConfig, run: Run = subprocess.run) -> tuple[pathlib.Path, pathlib.Path]:
    lock_path = config.destination_directory / ".wafio-backup.lock"
    with lock_path.open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BackupError("backup already in progress") from exc
        return _create_backup_locked(config, run)


def _create_backup_locked(config: BackupConfig, run: Run) -> tuple[pathlib.Path, pathlib.Path]:
    base = artifact_basename()
    artifact = config.destination_directory / f"{base}.tar.gpg"
    manifest = config.destination_directory / f"{base}.manifest.json"
    if artifact.exists() or manifest.exists():
        raise BackupError("backup destination already exists")

    with tempfile.TemporaryDirectory(prefix=".wafio-backup-", dir=config.destination_directory) as temp_name:
        temp = pathlib.Path(temp_name)
        dump = temp / "database.dump"
        archive = temp / "backup.tar"
        encrypted = temp / "backup.tar.gpg"
        _run_checked(run, pg_dump_command(config, dump), "database dump", env=postgres_environment(config.database_url_file))
        if not dump.is_file() or dump.stat().st_size == 0:
            raise BackupError("database dump is incomplete")
        metadata = {
            "format_version": FORMAT_VERSION,
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "database_format": "postgresql-custom",
            "included_paths": [str(path) for path in config.include_paths],
        }
        metadata_path = temp / "backup-metadata.json"
        metadata_path.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
        with tarfile.open(archive, "w") as tar:
            tar.add(dump, arcname="database.dump")
            tar.add(metadata_path, arcname="backup-metadata.json")
            for include in config.include_paths:
                _add_include(tar, include)
        command = [*_gpg_base(config), "--trust-model", "always", "--recipient", config.gpg_recipient, "--encrypt", "--output", str(encrypted), str(archive)]
        _run_checked(run, command, "encryption")
        if not encrypted.is_file() or encrypted.stat().st_size == 0:
            raise BackupError("encrypted artifact is incomplete")
        encrypted.chmod(0o600)
        with encrypted.open("rb") as completed:
            os.fsync(completed.fileno())
        _publish_exclusive(encrypted, artifact)
        artifact.chmod(0o600)

    manifest_value = {
        "format_version": FORMAT_VERSION,
        "artifact": artifact.name,
        "bytes": artifact.stat().st_size,
        "sha256": _sha256(artifact),
    }
    temporary_manifest = config.destination_directory / f".{manifest.name}.partial"
    try:
        with temporary_manifest.open("x") as output:
            json.dump(manifest_value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary_manifest.chmod(0o600)
        _publish_exclusive(temporary_manifest, manifest)
    finally:
        temporary_manifest.unlink(missing_ok=True)
    if config.s3_bucket:
        _upload_s3(config, (artifact, manifest), run)
    _prune(config)
    return artifact, manifest


def _read_manifest(artifact: pathlib.Path, manifest: pathlib.Path) -> dict:
    try:
        value = json.loads(manifest.read_text())
        artifact_size = artifact.stat().st_size
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("manifest is unreadable") from exc
    if value.get("format_version") != FORMAT_VERSION or value.get("artifact") != artifact.name:
        raise BackupError("manifest does not describe this artifact")
    if value.get("bytes") != artifact_size or value.get("sha256") != _sha256(artifact):
        raise BackupError("artifact checksum validation failed")
    return value


def validate_archive_names(names: Iterable[str]) -> None:
    for name in names:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise BackupError(f"unsafe archive path: {name}")
        if path.parts[0] not in ("database.dump", "backup-metadata.json", "files"):
            raise BackupError(f"unexpected archive path: {name}")


def validate_archive(archive: tarfile.TarFile) -> None:
    members = archive.getmembers()
    validate_archive_names(member.name for member in members)
    if any(member.issym() or member.islnk() or member.isdev() for member in members):
        raise BackupError("archive contains an unsafe member type")
    by_name = {member.name: member for member in members}
    if len(by_name) != len(members):
        raise BackupError("archive contains duplicate paths")
    dump = by_name.get("database.dump")
    if dump is None or not dump.isfile() or dump.size <= 0:
        raise BackupError("archive database.dump is missing or empty")
    metadata_member = by_name.get("backup-metadata.json")
    if metadata_member is None or not metadata_member.isfile() or metadata_member.size <= 0:
        raise BackupError("archive metadata is missing or empty")
    try:
        metadata_file = archive.extractfile(metadata_member)
        if metadata_file is None:
            raise ValueError("metadata is not readable")
        metadata = json.load(metadata_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise BackupError("archive metadata is invalid") from exc
    if not isinstance(metadata, dict):
        raise BackupError("archive metadata must be an object")
    if metadata.get("format_version") != FORMAT_VERSION or metadata.get("database_format") != "postgresql-custom":
        raise BackupError("archive metadata format is unsupported")


def _decrypt_archive(config: BackupConfig, artifact: pathlib.Path, manifest: pathlib.Path, destination: pathlib.Path, run: Run) -> pathlib.Path:
    _read_manifest(artifact, manifest)
    archive = destination / "backup.tar"
    command = [*_gpg_base(config), "--decrypt", "--output", str(archive), str(artifact)]
    _run_checked(run, command, "decryption")
    if not archive.is_file() or archive.stat().st_size == 0:
        raise BackupError("decrypted archive is incomplete")
    try:
        with tarfile.open(archive, "r") as tar:
            validate_archive(tar)
    except tarfile.TarError as exc:
        raise BackupError("decrypted archive is invalid") from exc
    return archive


def verify_backup(config: BackupConfig, artifact: pathlib.Path, manifest: pathlib.Path, run: Run = subprocess.run) -> None:
    with tempfile.TemporaryDirectory(prefix="wafio-verify-") as temp_name:
        _decrypt_archive(config, artifact, manifest, pathlib.Path(temp_name), run)


def _normalized_database_identity(database_url_file: pathlib.Path) -> tuple[str, int, str]:
    parsed = urllib.parse.urlparse(database_url_file.read_text().strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        if host == "localhost" or ipaddress.ip_address(host).is_loopback:
            host = "loopback"
    except ValueError:
        pass
    return host, parsed.port or 5432, urllib.parse.unquote(parsed.path.lstrip("/"))


def require_empty_restore_target(config: BackupConfig, target_database_url_file: pathlib.Path, run: Run = subprocess.run) -> dict[str, str]:
    _require_private_file(target_database_url_file, "target database URL file")
    if _normalized_database_identity(config.database_url_file) == _normalized_database_identity(target_database_url_file):
        raise BackupError("restore target is the source database")
    env = postgres_environment(target_database_url_file)
    query = (
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE c.relkind IN ('r','p','v','m','f','S') "
        "AND n.nspname NOT IN ('pg_catalog','information_schema') "
        "AND n.nspname NOT LIKE 'pg_toast%'"
    )
    try:
        result = run(
            [config.psql, "-X", "--no-password", "-At", "-v", "ON_ERROR_STOP=1", "-c", query],
            check=True, env=env, capture_output=True, text=True,
        )
        relation_count = int(result.stdout.strip())
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise BackupError("restore target emptiness check failed") from exc
    if relation_count != 0:
        raise BackupError("restore target database is not empty")
    return env


def restore_backup(
    config: BackupConfig,
    artifact: pathlib.Path,
    manifest: pathlib.Path,
    target_database_url_file: pathlib.Path,
    restore_directory: pathlib.Path,
    run: Run = subprocess.run,
) -> None:
    if restore_directory.exists():
        raise BackupError("restore directory already exists")
    env = require_empty_restore_target(config, target_database_url_file, run)
    restore_directory.mkdir(mode=0o700, parents=True)
    with tempfile.TemporaryDirectory(prefix=".decrypt-", dir=restore_directory) as temp_name:
        archive = _decrypt_archive(config, artifact, manifest, pathlib.Path(temp_name), run)
        with tarfile.open(archive, "r") as tar:
            tar.extractall(restore_directory, filter="data")
    dump = restore_directory / "database.dump"
    if not dump.is_file() or dump.stat().st_size == 0:
        raise BackupError("backup does not contain a database dump")
    _run_checked(run, [config.psql, "-X", "--no-password", "-v", "ON_ERROR_STOP=1", "-c", "CREATE EXTENSION IF NOT EXISTS timescaledb"], "Timescale extension setup", env=env)
    _run_checked(run, [config.psql, "-X", "--no-password", "-v", "ON_ERROR_STOP=1", "-c", "SELECT timescaledb_pre_restore()"], "Timescale pre-restore", env=env)
    _run_checked(run, [config.pg_restore, "--exit-on-error", "--no-password", "--dbname", env["PGDATABASE"], str(dump)], "database restore", env=env)
    _run_checked(run, [config.psql, "-X", "--no-password", "-v", "ON_ERROR_STOP=1", "-c", "SELECT timescaledb_post_restore()"], "Timescale post-restore", env=env)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("backup", "verify", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=pathlib.Path, required=True)
        if name != "backup":
            command.add_argument("--artifact", type=pathlib.Path, required=True)
            command.add_argument("--manifest", type=pathlib.Path, required=True)
        if name == "restore":
            command.add_argument("--target-database-url-file", type=pathlib.Path, required=True)
            command.add_argument("--restore-directory", type=pathlib.Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "backup":
            artifact, manifest = create_backup(config)
            print(json.dumps({"status": "complete", "artifact": str(artifact), "manifest": str(manifest)}))
        elif args.command == "verify":
            verify_backup(config, args.artifact, args.manifest)
            print(json.dumps({"status": "verified", "artifact": str(args.artifact)}))
        else:
            restore_backup(config, args.artifact, args.manifest, args.target_database_url_file, args.restore_directory)
            print(json.dumps({"status": "restored", "directory": str(args.restore_directory)}))
    except BackupError as exc:
        print(f"backup-controlplane: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
