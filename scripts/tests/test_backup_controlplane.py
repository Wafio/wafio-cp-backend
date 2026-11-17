import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).parents[1] / "backup-controlplane.py"
REPOSITORY = SCRIPT.parents[1]
SPEC = importlib.util.spec_from_file_location("backup_controlplane", SCRIPT)
backup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = backup
SPEC.loader.exec_module(backup)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.destination = self.root / "backups"
        self.destination.mkdir(mode=0o700)
        self.db_url = self.root / "database-url"
        self.db_url.write_text("postgresql://operator:secret@127.0.0.1:5433/wafio\n")
        self.db_url.chmod(0o600)
        self.config = self.root / "backup.json"

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, **overrides):
        value = {
            "database_url_file": str(self.db_url),
            "destination_directory": str(self.destination),
            "gpg_recipient": "backup@example.invalid",
        }
        value.update(overrides)
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)

    def test_missing_required_configuration_fails(self):
        self.write_config()
        value = json.loads(self.config.read_text())
        del value["gpg_recipient"]
        self.config.write_text(json.dumps(value))
        with self.assertRaisesRegex(backup.BackupError, "gpg_recipient"):
            backup.load_config(self.config)

    def test_rejects_group_readable_database_url(self):
        self.write_config()
        self.db_url.chmod(0o640)
        with self.assertRaisesRegex(backup.BackupError, "permissions"):
            backup.load_config(self.config)

    def test_rejects_group_accessible_destination(self):
        self.write_config()
        self.destination.chmod(0o750)
        with self.assertRaisesRegex(backup.BackupError, "permissions"):
            backup.load_config(self.config)

    def test_database_password_is_only_passed_in_environment(self):
        self.write_config()
        config = backup.load_config(self.config)
        env = backup.postgres_environment(config.database_url_file)
        self.assertEqual(env["PGPASSWORD"], "secret")
        self.assertNotIn("secret", " ".join(backup.pg_dump_command(config)))

    def test_explicit_url_removes_ambient_service_and_hostaddr_routing(self):
        self.write_config()
        hostile = {
            "PGSERVICE": "production",
            "PGSERVICEFILE": "/tmp/hostile-service",
            "PGHOSTADDR": "203.0.113.20",
        }
        with mock.patch.dict(os.environ, hostile):
            env = backup.postgres_environment(self.db_url)
        for name in hostile:
            self.assertNotIn(name, env)
        self.assertEqual(env["PGHOST"], "127.0.0.1")

    def test_supported_tls_and_timeout_url_parameters_are_preserved(self):
        self.db_url.write_text(
            "postgresql://operator:secret@db.internal:5433/wafio?"
            "sslmode=verify-full&sslrootcert=%2Fetc%2Fwafio%2Fca.pem&"
            "sslcert=%2Fetc%2Fwafio%2Fclient.pem&sslkey=%2Fetc%2Fwafio%2Fclient.key&"
            "connect_timeout=7"
        )
        env = backup.postgres_environment(self.db_url)
        self.assertEqual(env["PGSSLMODE"], "verify-full")
        self.assertEqual(env["PGSSLROOTCERT"], "/etc/wafio/ca.pem")
        self.assertEqual(env["PGSSLCERT"], "/etc/wafio/client.pem")
        self.assertEqual(env["PGSSLKEY"], "/etc/wafio/client.key")
        self.assertEqual(env["PGCONNECT_TIMEOUT"], "7")

    def test_unknown_or_repeated_database_url_parameters_are_rejected(self):
        for query in ("application_name=shadow", "sslmode=require&sslmode=disable"):
            with self.subTest(query=query):
                self.db_url.write_text(f"postgresql://operator@127.0.0.1/wafio?{query}")
                with self.assertRaisesRegex(backup.BackupError, "query parameter"):
                    backup.postgres_environment(self.db_url)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.destination = self.root / "backups"
        self.destination.mkdir(mode=0o700)
        self.db_url = self.root / "database-url"
        self.db_url.write_text("postgresql://operator:secret@127.0.0.1:5433/wafio\n")
        self.db_url.chmod(0o600)
        self.config_path = self.root / "backup.json"
        self.config_path.write_text(json.dumps({
            "database_url_file": str(self.db_url),
            "destination_directory": str(self.destination),
            "gpg_recipient": "recipient",
        }))
        self.config_path.chmod(0o600)
        self.config = backup.load_config(self.config_path)

    def tearDown(self):
        self.temp.cleanup()

    def test_existing_destination_collision_is_never_overwritten(self):
        artifact = self.destination / "wafio-controlplane-fixed.tar.gpg"
        artifact.write_bytes(b"existing")
        with mock.patch.object(backup, "artifact_basename", return_value="wafio-controlplane-fixed"):
            with self.assertRaisesRegex(backup.BackupError, "already exists"):
                backup.create_backup(self.config)
        self.assertEqual(artifact.read_bytes(), b"existing")

    def test_encryption_failure_publishes_nothing(self):
        def runner(command, **kwargs):
            if pathlib.Path(command[0]).name == "pg_dump":
                pathlib.Path(command[command.index("--file") + 1]).write_bytes(b"dump")
                return subprocess.CompletedProcess(command, 0)
            raise subprocess.CalledProcessError(2, command)

        with self.assertRaisesRegex(backup.BackupError, "encryption failed"):
            backup.create_backup(self.config, run=runner)
        self.assertEqual([p for p in self.destination.iterdir() if not p.name.startswith(".wafio-backup.lock")], [])

    def test_zero_length_encrypted_output_is_rejected(self):
        def runner(command, **kwargs):
            if pathlib.Path(command[0]).name == "pg_dump":
                pathlib.Path(command[command.index("--file") + 1]).write_bytes(b"dump")
            elif pathlib.Path(command[0]).name == "gpg":
                pathlib.Path(command[command.index("--output") + 1]).touch()
            return subprocess.CompletedProcess(command, 0)

        with self.assertRaisesRegex(backup.BackupError, "incomplete"):
            backup.create_backup(self.config, run=runner)
        self.assertEqual([p for p in self.destination.iterdir() if not p.name.startswith(".wafio-backup.lock")], [])

    def test_late_artifact_collision_never_overwrites_existing_data(self):
        existing = b"late-existing-backup"

        def runner(command, **kwargs):
            tool = pathlib.Path(command[0]).name
            if tool == "pg_dump":
                pathlib.Path(command[command.index("--file") + 1]).write_bytes(b"dump")
            elif tool == "gpg":
                pathlib.Path(command[command.index("--output") + 1]).write_bytes(b"new-encrypted")
                (self.destination / "wafio-controlplane-fixed.tar.gpg").write_bytes(existing)
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(backup, "artifact_basename", return_value="wafio-controlplane-fixed"):
            with self.assertRaisesRegex(backup.BackupError, "already exists"):
                backup.create_backup(self.config, run=runner)
        self.assertEqual((self.destination / "wafio-controlplane-fixed.tar.gpg").read_bytes(), existing)
        self.assertFalse((self.destination / "wafio-controlplane-fixed.manifest.json").exists())

    def test_upload_failure_keeps_local_artifact_and_manifest(self):
        config = backup.BackupConfig(**{
            **self.config.__dict__,
            "s3_endpoint_url": "https://minio.example.invalid",
            "s3_bucket": "authorized-backups",
            "s3_key_prefix": "control-plane",
        })

        def runner(command, **kwargs):
            tool = pathlib.Path(command[0]).name
            if tool == "pg_dump":
                pathlib.Path(command[command.index("--file") + 1]).write_bytes(b"dump")
            elif tool == "gpg":
                pathlib.Path(command[command.index("--output") + 1]).write_bytes(b"encrypted")
            elif tool == "aws":
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0)

        with self.assertRaisesRegex(backup.BackupError, "upload failed"):
            backup.create_backup(config, run=runner)
        published = [path for path in self.destination.iterdir() if path.name != ".wafio-backup.lock"]
        self.assertEqual(sorted(path.suffix for path in published), [".gpg", ".json"])
        for path in published:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_s3_contract_uses_endpoint_bucket_key_and_download_verification(self):
        aws_settings = self.root / "aws-config"
        aws_settings.write_text("[profile backup]\nregion = us-east-1\ns3 =\n  addressing_style = path\n")
        aws_settings.chmod(0o600)
        config = backup.BackupConfig(**{
            **self.config.__dict__,
            "s3_endpoint_url": "https://minio.example.invalid",
            "s3_bucket": "authorized-backups",
            "s3_key_prefix": "control-plane",
            "aws_profile": "backup",
            "aws_config_file": aws_settings,
        })
        uploaded = {}
        aws_calls = []

        def runner(command, **kwargs):
            tool = pathlib.Path(command[0]).name
            if tool == "pg_dump":
                pathlib.Path(command[command.index("--file") + 1]).write_bytes(b"dump")
            elif tool == "gpg":
                pathlib.Path(command[command.index("--output") + 1]).write_bytes(b"encrypted")
            elif tool == "aws":
                aws_calls.append((command, kwargs))
                key = command[command.index("--key") + 1]
                if "put-object" in command:
                    uploaded[key] = pathlib.Path(command[command.index("--body") + 1]).read_bytes()
                else:
                    pathlib.Path(command[-1]).write_bytes(uploaded[key])
            return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

        backup.create_backup(config, run=runner)
        self.assertEqual(len(aws_calls), 4)
        artifact_put = aws_calls[0]
        self.assertIn("https://minio.example.invalid", artifact_put[0])
        self.assertIn("authorized-backups", artifact_put[0])
        self.assertIn("control-plane/wafio-controlplane-", " ".join(artifact_put[0]))
        self.assertIn("--checksum-sha256", artifact_put[0])
        self.assertEqual(artifact_put[1]["env"]["AWS_CONFIG_FILE"], str(aws_settings))
        self.assertNotIn("secret", " ".join(artifact_put[0]))


class ArchiveValidationTests(unittest.TestCase):
    def test_rejects_parent_traversal(self):
        with self.assertRaisesRegex(backup.BackupError, "unsafe archive path"):
            backup.validate_archive_names(["database.dump", "../operator-key"])

    def test_accepts_expected_backup_layout(self):
        backup.validate_archive_names([
            "backup-metadata.json",
            "database.dump",
            "files/etc/wafio/config.yaml",
        ])

    def make_archive(self, members):
        archive = pathlib.Path(self.temp.name) / "backup.tar"
        with tarfile.open(archive, "w") as tar:
            for name, value in members.items():
                source = pathlib.Path(self.temp.name) / name.replace("/", "-")
                source.write_bytes(value)
                tar.add(source, arcname=name)
        return archive

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_requires_nonempty_database_dump(self):
        archive = self.make_archive({
            "database.dump": b"",
            "backup-metadata.json": b'{"format_version":1,"database_format":"postgresql-custom"}',
        })
        with tarfile.open(archive) as tar:
            with self.assertRaisesRegex(backup.BackupError, "database.dump"):
                backup.validate_archive(tar)

    def test_archive_requires_valid_versioned_metadata(self):
        archive = self.make_archive({
            "database.dump": b"dump",
            "backup-metadata.json": b'{"format_version":99,"database_format":"postgresql-custom"}',
        })
        with tarfile.open(archive) as tar:
            with self.assertRaisesRegex(backup.BackupError, "metadata"):
                backup.validate_archive(tar)

    def test_archive_metadata_must_be_an_object(self):
        for value in (b"[]", b"null"):
            with self.subTest(value=value):
                archive = self.make_archive({
                    "database.dump": b"dump",
                    "backup-metadata.json": value,
                })
                with tarfile.open(archive) as tar:
                    with self.assertRaisesRegex(backup.BackupError, "metadata"):
                        backup.validate_archive(tar)

    def test_archive_requires_both_mandatory_members(self):
        archive = self.make_archive({"backup-metadata.json": b'{"format_version":1}'})
        with tarfile.open(archive) as tar:
            with self.assertRaisesRegex(backup.BackupError, "database.dump"):
                backup.validate_archive(tar)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.destination = pathlib.Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def add_pair(self, base, valid=True):
        artifact = self.destination / f"{base}.tar.gpg"
        manifest = self.destination / f"{base}.manifest.json"
        artifact.write_bytes(base.encode())
        manifest.write_text(json.dumps({
            "format_version": backup.FORMAT_VERSION,
            "artifact": artifact.name,
            "bytes": artifact.stat().st_size,
            "sha256": backup._sha256(artifact) if valid else "0" * 64,
        }))
        return artifact, manifest

    def test_orphan_and_invalid_newer_manifests_do_not_consume_retention_slots(self):
        older = self.add_pair("wafio-controlplane-20260912T000001Z")
        newer = self.add_pair("wafio-controlplane-20260912T000002Z")
        self.add_pair("wafio-controlplane-20260912T000004Z", valid=False)
        (self.destination / "wafio-controlplane-20260912T000003Z.manifest.json").write_text("{}")
        config = backup.BackupConfig(
            database_url_file=self.destination / "unused",
            destination_directory=self.destination,
            gpg_recipient="unused",
            retention_count=2,
        )
        backup._prune(config)
        self.assertTrue(all(path.exists() for path in (*older, *newer)))


class RestoreSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.source = self.root / "source-url"
        self.target = self.root / "target-url"
        self.source.write_text("postgresql://operator:secret@localhost:5433/wafio")
        self.target.write_text("postgresql://operator:secret@127.0.0.1:5433/recovery")
        self.source.chmod(0o600)
        self.target.chmod(0o600)
        self.config = backup.BackupConfig(
            database_url_file=self.source,
            destination_directory=self.root,
            gpg_recipient="unused",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_source_database_identity_before_any_database_call(self):
        self.target.write_text("postgresql://other:other@127.0.0.1:5433/wafio")
        calls = []
        with self.assertRaisesRegex(backup.BackupError, "source database"):
            backup.restore_backup(
                self.config, self.root / "missing.gpg", self.root / "missing.json",
                self.target, self.root / "restore", run=lambda *a, **k: calls.append(a),
            )
        self.assertEqual(calls, [])
        self.assertFalse((self.root / "restore").exists())

    def test_rejects_populated_target_before_mutating_database(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="1\n", stderr="")

        with self.assertRaisesRegex(backup.BackupError, "not empty"):
            backup.restore_backup(
                self.config, self.root / "missing.gpg", self.root / "missing.json",
                self.target, self.root / "restore", run=runner,
            )
        self.assertEqual(len(calls), 1)
        self.assertIn("SELECT count", " ".join(calls[0]))
        self.assertNotIn("CREATE EXTENSION", " ".join(calls[0]))
        self.assertNotIn("pre_restore", " ".join(calls[0]))
        self.assertFalse((self.root / "restore").exists())


class SystemdTemplateTests(unittest.TestCase):
    def test_gpg_home_is_writable_state_not_readonly_configuration(self):
        service = (REPOSITORY / "deploy/systemd/wafio-controlplane-backup.service").read_text()
        runbook = (REPOSITORY / "docs/operations/production-backup.md").read_text()
        self.assertIn("StateDirectory=wafio-backup", service)
        self.assertIn('"gpg_homedir": "/var/lib/wafio-backup/gnupg"', runbook)
        self.assertNotIn('"gpg_homedir": "/etc/wafio', runbook)


if __name__ == "__main__":
    unittest.main()
