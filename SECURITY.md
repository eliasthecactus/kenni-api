# Security model

KENNI's backend is a **blind relay** plus a small business directory. It is designed
so that compromising the server does not compromise anyone's identity or let anyone be
impersonated to their contacts.

## What the server can and cannot do

- **Cannot** read names, photos, contacts, or message content — profile data
  never reaches it, verification payloads are opaque signed envelopes, and family
  alerts are encrypted on the phone with the pairwise key.
- **Cannot** forge a verification: every request/response is signed on-device
  with an Ed25519 key, and verified on the recipient's device against the public
  key exchanged out-of-band (QR/link). The server holds no signing keys. Live
  Activity updates only say "answered"; the verdict is decided in the app.
- **Cannot** introduce a contact: identities are exchanged directly between
  users. The server only relays.
- **Stores** only what routing needs: public key ↔ APNs token registrations,
  short-lived envelopes (verification requests: 90 s, family alerts: 24 h), an
  optional client-side-encrypted backup blob it cannot read, and the blocks a key
  asked for. `DELETE /v1/me` removes all of it.
- **Business directory:** the server *is* the trust anchor for "this is an approved
  business". A compromised server or super-admin account could approve a fake
  business, which is why the admin sign-in needs a second factor and every
  action is audited.

## Request authentication

Every authenticated endpoint requires a signature over

    kenni/v2/{context}\n{host}\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{body}

(`context` = `api` or `business-device`) with the caller's Ed25519 key. The server
checks a ±300 s timestamp window and accepts each `(key, nonce)` once (database
replay cache), so captured requests can't be replayed — here or, because the host
is signed, against another instance. App versions ≤ 1.0.2 sign the older v1 format
without host and nonce; those are replay-cached by signature and can be switched
off with `ACCEPT_LEGACY_SIGNATURES=false`.

## Anti-abuse

- Rate limits per client IP (`RATE_LIMIT`), per signing key, per recipient and per
  sender→recipient pair; family alerts and outbound verifications have their own.
- Client IPs come from `X-Forwarded-For` only via trusted proxies (`TRUST_PROXY`).
- Wrong business PINs draw from a global budget (`PIN_FAILURE_BUDGET`), on top of the
  per-IP limit, so guessing can't be spread across many addresses.
- Recipients can block a key; blocked senders get the same 404 as an unknown key.
- Request-body cap (2 MB), per-endpoint payload limits, strict input validation.
- APNs tokens reported dead by Apple are removed.
- Conservative security headers on every response; the admin portal has a strict CSP,
  per-session CSRF tokens and HTTP-only cookies.

## Residual risks

- **Recipient enumeration:** `POST /v1/verify/requests` returns 404 for an
  unregistered (or blocking) target, which reveals whether a key is registered.
  Keys are exchanged privately, so exposure is limited.
- **Business PIN relay:** a scammer who gets a real PIN from a business during a
  parallel call can pass it on within 90 s. The customer sees the representative's
  name and the app asks them to only trust PINs from a call *they* placed;
  outbound verifications (business → customer's KENNI ID) avoid the problem for
  calls the business makes.
- **In-memory rate limiter** is per instance (see README).

## Deployment notes

- Never commit the APNs `.p8`; provide it via `APNS_KEY_P8` (or a mounted file
  referenced by `APNS_KEY_PATH`). Both are gitignored.
- Keep `BUSINESS_TOKEN_SECRET` stable and secret: rotating it invalidates
  enrollment links, PINs and stored SSO client secrets.
- Optionally set `ADMIN_TOTP_SECRET` for a second factor; without it the sign-in needs
  only `ADMIN_PSK` and the API logs a warning at startup.
- Run behind TLS (Coolify/Traefik terminate it at `kenniapi.benavo.ch`).

## Reporting

Found something? Email **kenni@benavo.ch**. Please don't open a public issue for
security reports.
