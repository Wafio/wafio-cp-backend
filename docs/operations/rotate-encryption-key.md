# Change the encryption key (`totp.enc_key`)

`totp.enc_key` encrypts five kinds of value in the control plane database: the TOTP secrets of users (`users.totp_secret`), the secrets that wait for a first code (`users.totp_pending_secret`), the SMTP password saved under Administration > Email (SMTP), the MalwareBazaar key saved under Administration > Security data, and the private keys of uploaded TLS certificates. Setting a new key in the configuration alone makes all of them unreadable: 2FA users cannot sign in, the mail and malware settings lose their secrets, and every certificate that was uploaded must be uploaded again. `wafio rekey` rewrites the values from the old key to the new one first. Its flags and rules are in `docs/cli.md`.

Change the key when it may have leaked, when a person who knew it leaves, or on the schedule the operator keeps for secrets. Nothing else uses it: the host keys, the agent credentials and the mTLS CA are not touched.

## Steps

1. Take a backup of the database and of `config/config.yaml` (`production-backup.md`). Keep the old key; the backup holds values sealed with it.
2. Generate the new key: `openssl rand -hex 32`.
3. Stop the control plane. `rekey` locks the rows it rewrites, but a secret that a running server saves after the read would be missed.
4. Put the new key in `totp.enc_key` (or `WAFIO_TOTP_ENC_KEY`). Keep the old key in a shell variable that is not written to the history, for example `read -rs WAFIO_OLD_TOTP_ENC_KEY; export WAFIO_OLD_TOTP_ENC_KEY`.
5. Run `wafio rekey` without a flag. It changes nothing and prints how many values of each kind it would rewrite. The last column, unreadable, must be 0 for every kind. A value is unreadable when neither key opens it: it was sealed with a third key, or the row is damaged. The report names the row by user id, certificate id or setting name. Find the key that sealed it and give that one in `WAFIO_OLD_TOTP_ENC_KEY`, or deal with the rows (a user can enrol 2FA again, a certificate can be uploaded again) before going on.
6. Run `wafio rekey --apply`. It rewrites every value in one transaction and prints the number it rewrote. If it fails, nothing was written and it can be run again.
7. Start the control plane with the new key. Check one value of each kind that matters to the installation: sign in with a 2FA account, send the test email under Administration > Email (SMTP), and look at an application that serves an uploaded certificate.
8. Destroy the old key when the last backup that holds values sealed with it has expired or been re-taken.

## Good to know

- Running `rekey` again is safe. A value that already opens with the new key counts as done, so a run after the control plane was started with the new key (new 2FA enrolments are sealed with it) rewrites only what is left.
- Values stored in plain text are left as they are. A TOTP secret from before encryption was enabled is read as plain text and sealed when its user enrols again.
- A key given in `WAFIO_MALWARE_AUTH_KEY` or `smtp.password` is not stored in the database and is not part of this.
- The old and the new key must differ. The command compares what they decrypt, so the same key in hex and in base64 is refused as well.
- A certificate key that does not open with the configured key is reported as `key_unreadable` when an agent asks for it. If the control plane ran with the new key before `rekey`, `wafio rekey --apply` fixes that without another upload.
