# Change the encryption key (`totp.enc_key`)

`totp.enc_key` encrypts five kinds of value in the control plane database: the TOTP secrets of users (`users.totp_secret`), the secrets that wait for a first code (`users.totp_pending_secret`), the SMTP password saved under Administration > Email (SMTP), the MalwareBazaar key saved under Administration > Security data, and the private keys of uploaded TLS certificates. Setting a new key in the configuration alone makes all of them unreadable: 2FA users cannot sign in, the mail and malware settings lose their secrets, and every certificate that was uploaded must be uploaded again. `wafio rekey` rewrites the values from the old key to the new one first. Its flags and rules are in `docs/cli.md`.

Change the key when it may have leaked, when a person who knew it leaves, or on the schedule the operator keeps for secrets. Nothing else uses it: the host keys, the agent credentials and the mTLS CA are not touched.

## How the control plane and the command stay in step

Every control plane holds a lock on the key for as long as it runs, and `wafio rekey --apply` refuses while one does. A control plane also compares the id of its `totp.enc_key` (a short fingerprint, not the key) with the id the database holds, and refuses to start when they differ. Together they mean that no server can seal a new secret with the old key after the rewrite, and none can start with the new key before it. The id moves to the new key in the same transaction that rewrites the values.

## Steps

1. Take a backup of the database and of `config/config.yaml` (`production-backup.md`). Keep the old key; the backup holds values sealed with it.
2. Generate the new key: `openssl rand -hex 32`.
3. Stop every control plane (every `wafio serve`, on every host that runs one). `--apply` refuses while any of them runs.
4. Put the new key in `totp.enc_key` (or `WAFIO_TOTP_ENC_KEY`).
5. Read the old key into a shell variable without echoing it, and run the command with it on the same line, so that it is in the environment of that one command only (the command removes it from its own environment as soon as it has read it):

   ```
   read -rs old
   WAFIO_OLD_TOTP_ENC_KEY="$old" wafio rekey
   ```

   Without a flag it changes nothing and prints how many values of each kind it would rewrite. The last column, unreadable, must be 0 for every kind. A value is unreadable when neither key opens it: it was sealed with a third key, or the row is damaged. The report names the row by user id, certificate id or setting name. Find the key that sealed it and give that one, or deal with the rows (a user can enrol 2FA again, a certificate can be uploaded again) before going on.
6. Run it again with `--apply`, then remove the variable:

   ```
   WAFIO_OLD_TOTP_ENC_KEY="$old" wafio rekey --apply
   unset old
   ```

   It rewrites every value in one transaction, records the rotation in the audit log (`admin.encryption_key_rotated`, with the two key ids and the counts) and prints the number it rewrote. If it fails, nothing was written and it can be run again. Three things stop it before it writes: a control plane that still runs ("stop every wafio serve"), a value that neither key opens, and a row that another transaction has held for more than 10 seconds (find it in `pg_stat_activity`).
7. Start the control plane with the new key. Check one value of each kind that matters to the installation: sign in with a 2FA account, send the test email under Administration > Email (SMTP), and look at an application that serves an uploaded certificate.
8. Destroy the old key when the last backup that holds values sealed with it has expired or been re-taken.

## Good to know

- A control plane started with the new key before step 6 refuses to start and names the two key ids. Put the old key back, or finish the rotation. Starting it with the old key after step 6 is refused the same way.
- Running `rekey` again is safe. A value that already opens with the new key counts as done, so a run that was cut short, or a rotation of a database that was rewritten before, rewrites only what is left.
- Values stored in plain text are left as they are. A TOTP secret from before encryption was enabled is read as plain text and sealed when its user enrols again.
- A key given in `WAFIO_MALWARE_AUTH_KEY` or `smtp.password` is not stored in the database and is not part of this.
- The old and the new key must differ. The command compares what they decrypt, so the same key in hex and in base64 is refused as well.
- A certificate key that does not open with the configured key is reported as `key_unreadable` when an agent asks for it. `wafio rekey --apply` fixes that without another upload.
- The first start of an installation that was running before the id existed stores the id of the key it starts with. If the key was changed by hand before that start, the id is the wrong one: change it back to the key that sealed the data, or upload the certificates and enrol 2FA again.
