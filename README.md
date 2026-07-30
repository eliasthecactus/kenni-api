# kenni-api

Backend for [KENNI](https://benavo.ch/apps/kenni). Contact exchange and all verification
cryptography happen **on-device**; the relay only sees signed, opaque envelopes. It also
serves administrator-approved public business profiles when a user supplies the business PIN.

There are no user accounts, emails, user names, or analytics. The relay holds no identity
private keys and cannot read or forge verification payloads. See [`SECURITY.md`](SECURITY.md)
for the threat model.

- **Stack:** Swift Vapor 4, Fluent + PostgreSQL (SQLite for local/tests), APNSwift (token `.p8` auth)
- **Deploy:** multi-stage Docker → Coolify → `https://kenniapi.benavo.ch`

## What it does

| Method & path | Purpose |
|---|---|
| `GET /health` | Health probe |
| `POST /v1/devices` | Register/refresh this device's public key ↔ APNs token, so verification requests can reach it |
| `POST /v1/verify/requests` | Relay a live-check request to a target device + send a push |
| `POST /v1/verify/requests/:id/response` | Relay the recipient's signed answer back + push |
| `GET /v1/verify/requests/:id` | Poll fallback if a push was missed |
| `PUT` / `GET /v1/backup` | Optional client-side-encrypted contacts backup (opaque blob) |
| `POST /v1/businesses/identify` | Reveal an approved public business profile using its six-digit PIN (unsigned, 10 attempts/min/IP) |
| `GET /admin` | Server-rendered business administration portal |

Every authenticated request is signed with the caller's Ed25519 key
(`X-Kenni-Id` / `X-Kenni-Timestamp` / `X-Kenni-Signature`) — proof of key possession, no
accounts. Verification payloads are opaque signed envelopes; they're verified on the phones,
never here.

> Contact exchange has **no endpoint** — the app shares a `kenni://` link with the signed
> identity card embedded, so it works fully offline without the server.

The admin portal uses an eight-hour, HTTP-only session after shared-PSK authentication.
Business PINs are stored only as keyed HMAC digests. If either admin environment variable is
missing, the portal is locked; the PIN lookup is unavailable without its digest secret.

## Config (env)

See [`.env.example`](.env.example). Business administration requires `ADMIN_PSK` and a
separate, stable `BUSINESS_PIN_SECRET`. Other key vars: `DATABASE_URL`, `APNS_KEY_P8` (or
`APNS_KEY_PATH`), `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_ENV`, `RATE_LIMIT`.

## Local dev

```sh
docker compose up        # API + Postgres
# or, against SQLite:
swift run App serve
swift test
```

Send a test push once APNs is configured:

```sh
swift run App push-test <device-token>
```
