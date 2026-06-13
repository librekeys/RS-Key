# OATH — TOTP / HOTP codes

The device stores authenticator-app secrets and computes the 6/8-digit codes
on-card (YKOATH protocol). Up to 255 accounts. Clients: `ykman oath` and
Yubico Authenticator (desktop + mobile via USB).

## Add accounts

```sh
ykman oath accounts add github --issuer GitHub      # paste the base32 secret
# or straight from the otpauth:// URI / QR payload:
ykman oath accounts uri 'otpauth://totp/GitHub:me?secret=…&issuer=GitHub'
```

Options that matter:

- `--touch` — computing this account's code requires a button press.
- `--oath-type HOTP` for counter-based accounts (default is TOTP).
- 6/7/8 digits, SHA1/SHA256/SHA512 — all supported.

## Get codes

```sh
ykman oath accounts code            # all accounts (touch-required ones skipped)
ykman oath accounts code github     # one account (waits for touch if set)
```

Yubico Authenticator shows them live and refreshes every period.

## Protect the applet (optional)

```sh
ykman oath access change            # set a password
ykman oath access remember          # cache it on this host
```

Without a password the account list is readable by anything that can reach
the CCID interface; the password (and per-account `--touch`) is the opt-in
hardening. Brute-forcing the password over the wire is not practical
(full-length validation, no one-byte oracle).

## Manage

```sh
ykman oath accounts list
ykman oath accounts rename github GitHub:work
ykman oath accounts delete github
ykman oath reset                    # wipe the OATH applet only
```

## Notes

- Secrets live in device flash, sealed under the device root (and the OTP
  master key once [provisioned](../production.md)); codes are computed on-card,
  so the secret never returns to the host after `add`.
- OATH accounts are **not** covered by the [seed backup](seed-backup.md):
  keep your otpauth URIs/QRs somewhere safe, or re-enroll on loss.
- HOTP counters are persisted; touch-required HOTP accounts only burn their
  counter after the touch (no drive-by increments).
