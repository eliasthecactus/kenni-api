# Security model

KENNI's backend is a **blind relay**. It is designed so that compromising the
server does not compromise anyone's identity or let anyone be impersonated.

## What the server can and cannot do

- **Cannot** read names, photos, contacts, or message content — profile data
  never reaches it, and verification payloads are opaque signed envelopes.
- **Cannot** forge a verification: every request/response is signed on-device
  with an Ed25519 key, and verified on the recipient's device against the public
  key exchanged out-of-band (QR/link). The server holds no signing keys.
- **Cannot** introduce a contact: identities are exchanged directly between
  users. The server only relays.
- **Stores** only what routing needs: a public key ↔ APNs token mapping,
  short-lived signed envelopes (verification requests: 90 s, exchange tokens:
  7 days), and an optional client-side-encrypted backup blob it cannot read.

## Request authentication

Every authenticated endpoint requires a signature over
`kenni/v1/api\n{METHOD}\n{path}\n{timestamp}\n{body}` using the caller's Ed25519
key (`X-Kenni-Id` / `X-Kenni-Timestamp` / `X-Kenni-Signature`). The server
verifies the signature and a ±300 s timestamp window. This proves key possession
without any account system.

## Anti-abuse

- Per-IP rate limiting (`RATE_LIMIT`, default 120/min; `/health` exempt).
- Request-body cap (2 MB) and per-endpoint payload size limits.
- Input validation: APNs tokens must be hex; exchange bundles must carry the
  `KENNI1:` prefix and a sane length.
- 128-bit random exchange tokens, expiring after 7 days; unique request ids
  reject verification replays; verification requests expire after 90 s.
- TTL cleanup job purges expired rows.
- Conservative security headers on every response.

## Residual risks (accepted for v1)

- **Signature replay window:** a captured signed request could be replayed within
  the ±300 s timestamp window. Impact is bounded per endpoint — device/backup
  writes are idempotent, and verification requests are deduplicated by id — and
  TLS makes capture hard. A per-request nonce cache could close it entirely.
- **Recipient enumeration:** `POST /v1/verify/requests` returns 404 for an
  unregistered target, which reveals whether a given public key is registered.
  Keys are exchanged privately, so exposure is limited.
- **Signatures are not domain-bound:** a signature is valid against any KENNI
  API instance. Harmless with a single canonical instance; bind an audience if
  you run several.
- **In-memory rate limiter** is per-instance (see Deployment notes).

## Deployment notes

- Never commit the APNs `.p8`; provide it via `APNS_KEY_P8` (or a mounted file
  referenced by `APNS_KEY_PATH`). Both are gitignored.
- The in-memory rate limiter is per-instance. Behind multiple replicas, add a
  shared limiter or edge protection (e.g. Cloudflare).
- Run behind TLS (Coolify/Traefik terminate it at `kenniapi.benavo.ch`).

## Reporting

Found something? Email **kenni@benavo.ch**. Please don't open a public issue for
security reports.
