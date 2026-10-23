# kenni-api

Backend for [KENNI](https://benavo.ch/apps/kenni). Contact exchange and all verification
cryptography happen **on-device**; the relay only sees signed, opaque envelopes. It also
runs the approved-business directory: device enrollment, one-time PINs and outbound
verifications.

There are no user accounts, emails, user names, or analytics. The relay holds no identity
private keys and cannot read or forge verification payloads. See [`SECURITY.md`](SECURITY.md)
for the threat model.

- **Stack:** Swift Vapor 4, Fluent + PostgreSQL (SQLite for local/tests), APNSwift (token `.p8` auth)
- **Deploy:** multi-stage Docker → Coolify → `https://kenniapi.benavo.ch`

## Endpoints

| Method & path | Purpose |
|---|---|
| `GET /health` · `GET /livez` | Readiness (checks the database) · liveness |
| `GET /metrics` | Prometheus counters (only with `METRICS_TOKEN`) |
| `POST` / `DELETE /v1/devices` | Register or remove this installation's APNs token (several per key) |
| `DELETE /v1/me` | Erase everything the relay holds for the calling key |
| `POST /v1/blocks` · `DELETE /v1/blocks/:key` | Stop relaying anything from a key |
| `POST /v1/verify/requests` | Relay a live-check request to all of the target's devices + push |
| `POST /v1/verify/requests/:id/response` | Relay the recipient's signed answer back + push (+ Live Activity update) |
| `GET /v1/verify/requests/:id` | Poll fallback if a push was missed |
| `POST /v1/alerts` · `GET /v1/alerts/:id` | Family alerts (payload encrypted on the phone) |
| `PUT` / `GET` / `DELETE /v1/backup` | Optional client-side-encrypted contacts backup (opaque blob) |
| `POST /v1/business-device-invitations/claim` | Consume a one-time admin invitation and bind a business-device key |
| `GET /v1/business-devices/me` | The device, its business and its status (active / suspended / revoked) |
| `PUT /v1/business-devices/apns-token` · `PUT …/agent` | Push registration · representative name shown to customers |
| `POST /v1/business-devices/verification-pins` · `GET …/current` | Issue a one-time PIN · see when it is used |
| `POST /v1/business-devices/outbound-verifications` · `GET …/:id` | Confirm to a customer (by KENNI ID) who is contacting them · read the answer |
| `GET` / `POST /v1/outbound-verifications/:id(/response)` | The customer's side of an outbound verification |
| `POST /v1/business-verifications/verify` | Consume a PIN and return the business + representative |
| `GET /v1/businesses/:id/logo` | Hosted business logo |
| `GET /admin` | Server-rendered administration portal |

Every authenticated request is signed with the caller's Ed25519 key
(`X-Kenni-Id` / `X-Kenni-Timestamp` / `X-Kenni-Nonce` / `X-Kenni-Signature`; business
devices use the `X-Kenni-Business-*` equivalents). Signatures bind the host name and a
nonce, and each one is accepted once. See `KenniAuth.swift`.

> Contact exchange has **no endpoint** — the app shares a `kenni://` link with the signed
> identity card embedded, so it works fully offline without the server.

## Administration

- **KENNI super admins** sign in at `/admin` with `ADMIN_PSK`. If `ADMIN_TOTP_SECRET` is
  set, they also need an authenticator code (generate the secret with
  `swift run App admin-totp-secret`, anywhere — it is just a random value). They approve,
  edit, suspend and delete businesses, upload logos and set up company sign-in.
- **Business admins** sign in with their company's OpenID Connect provider (Entra ID,
  Google Workspace, Okta, …) via their organisation ID, and manage only their own
  business's devices: enrollment QR codes, revocation, cancelling invitations. Register
  `<PUBLIC_BASE_URL>/admin/sso/callback` as the redirect URI at the provider.
- Sessions are stored server-side (8 h, revocable, "sign out all other sessions").
- Every admin and business-device action is written to the audit log shown in the portal.
- Enrollment links and PINs are stored only as keyed HMAC digests; SSO client secrets are
  encrypted with a key derived from `BUSINESS_TOKEN_SECRET`.

## Client IPs and rate limits

Rate limits key on the client IP, which only trusted proxies may report through
`X-Forwarded-For` (`TRUST_PROXY`, see `.env.example`). The default trusts loopback and
private networks, which is right when Coolify's Traefik is the only proxy.

**With a CDN or second proxy in front of Traefik** (Cloudflare or any other), two things
are needed:

1. Traefik must keep the CDN's `X-Forwarded-For` instead of replacing it. This is a
   Traefik *entrypoint* setting, so it can't go into the service's labels. In Coolify →
   *Servers* → your server → *Proxy*, add to the Traefik `command:` list:
   ```yaml
   - '--entrypoints.http.forwardedHeaders.insecure=true'
   - '--entrypoints.https.forwardedHeaders.insecure=true'
   ```
   then restart the proxy. This works with any CDN. The trade-off: a client that reaches
   the server directly, bypassing the CDN, can choose the address the per-IP limit sees.
   The per-key, per-recipient and global PIN limits still apply. For a strict setup, use
   `forwardedHeaders.trustedIPs=<CDN ranges>` instead of `insecure=true`.
2. On the kenni-api service set `TRUST_PROXY=2` (CDN + Traefik).

Signed requests are also limited per key (offices behind one NAT don't share a budget),
recipients per sender, and wrong business PINs draw from a global budget. The limiter is
in memory: with several replicas, add a shared limiter in front.

## Config (env)

See [`.env.example`](.env.example).

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
