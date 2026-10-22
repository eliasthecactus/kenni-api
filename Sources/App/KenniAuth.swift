import Crypto
import Fluent
import Vapor

/// Proof-of-key authentication. Every authenticated request carries:
///
///   X-Kenni-Id:        base64url Ed25519 public key (32 bytes)
///   X-Kenni-Timestamp: unix seconds, must be within ±300 s
///   X-Kenni-Nonce:     base64url random bytes, unique per request (v2)
///   X-Kenni-Signature: base64url Ed25519 signature over
///                      v2: "kenni/v2/api\n{host}\n{METHOD}\n{path}\n{timestamp}\n{nonce}\n{body}"
///                      v1: "kenni/v1/api\n{METHOD}\n{path}\n{timestamp}\n{body}"   (legacy apps)
///
/// v2 binds the signature to this server's host name and makes every request
/// unique, so a captured request can't be replayed here or against another
/// instance. Both versions go through the replay cache.
///
/// The server learns *that* the caller owns the key — never anything about
/// who the person is.
struct KenniAuth {
    let keyID: String
    let publicKey: Curve25519.Signing.PublicKey

    static func verify(_ req: Request) async throws -> KenniAuth {
        guard
            let keyID = req.headers.first(name: "X-Kenni-Id"),
            let keyData = Data(base64URLEncoded: keyID), keyData.count == 32,
            let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        else {
            throw Abort(.unauthorized, reason: "missing or malformed auth headers")
        }
        try await SignedRequest.verify(
            req, context: "api", signer: keyID, publicKey: publicKey,
            timestampHeader: "X-Kenni-Timestamp", signatureHeader: "X-Kenni-Signature")
        try await req.enforce(req.application.rateLimits.perKey, key: "key:\(keyID)")
        return KenniAuth(keyID: keyID, publicKey: publicKey)
    }
}

enum SignedRequest {
    static let nonceHeader = "X-Kenni-Nonce"
    static let window: TimeInterval = 300

    static func message(context: String, host: String?, method: String, path: String,
                        timestamp: String, nonce: String?, body: String) -> Data {
        if let nonce {
            return Data("kenni/v2/\(context)\n\(host ?? "")\n\(method)\n\(path)\n\(timestamp)\n\(nonce)\n\(body)".utf8)
        }
        return Data("kenni/v1/\(context)\n\(method)\n\(path)\n\(timestamp)\n\(body)".utf8)
    }

    /// Checks timestamp, signature and replay. `signer` scopes the replay cache.
    static func verify(_ req: Request, context: String, signer: String,
                       publicKey: Curve25519.Signing.PublicKey,
                       timestampHeader: String, signatureHeader: String) async throws {
        guard let timestampRaw = req.headers.first(name: timestampHeader),
              let timestamp = Double(timestampRaw),
              let signatureRaw = req.headers.first(name: signatureHeader),
              let signature = Data(base64URLEncoded: signatureRaw) else {
            throw Abort(.unauthorized, reason: "missing or malformed auth headers")
        }
        guard abs(Date().timeIntervalSince1970 - timestamp) <= window else {
            throw Abort(.unauthorized, reason: "timestamp outside allowed window")
        }

        let nonce = req.headers.first(name: nonceHeader)
        if let nonce {
            guard (16...64).contains(nonce.count), Data(base64URLEncoded: nonce) != nil else {
                throw Abort(.unauthorized, reason: "malformed nonce")
            }
        } else if !req.application.acceptsLegacySignatures {
            throw Abort(.unauthorized, reason: "this app version is no longer supported")
        }

        let body = req.body.data.map(String.init(buffer:)) ?? ""
        let host = req.headers.first(name: .host)?.lowercased()
        let signed = message(context: context, host: host, method: req.method.rawValue,
                             path: req.url.path, timestamp: timestampRaw, nonce: nonce,
                             body: body)
        guard publicKey.isValidSignature(signature, for: signed) else {
            throw Abort(.unauthorized, reason: "invalid signature")
        }

        // One use per (signer, nonce) — or per signature for legacy clients.
        let replayMaterial = nonce.map { "\(context)\n\(signer)\n\($0)" } ?? signatureRaw
        try await UsedNonce.consume(
            digest: SHA256.hash(data: Data(replayMaterial.utf8)).hex,
            expiresAt: Date(timeIntervalSince1970: timestamp + window),
            on: req.db)
    }
}

/// Replay cache: a signed request may be accepted once while its timestamp is valid.
final class UsedNonce: Model, @unchecked Sendable {
    static let schema = "used_nonces"

    @ID(custom: "digest", generatedBy: .user) var id: String?
    @Field(key: "expires_at") var expiresAt: Date

    init() {}
    init(digest: String, expiresAt: Date) {
        self.id = digest
        self.expiresAt = expiresAt
    }

    static func consume(digest: String, expiresAt: Date, on db: any Database) async throws {
        do {
            try await UsedNonce(digest: digest, expiresAt: expiresAt).create(on: db)
        } catch let error as any DatabaseError where error.isConstraintFailure {
            throw Abort(.unauthorized, reason: "replayed request")
        }
    }
}

struct CreateUsedNonces: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(UsedNonce.schema)
            .field("digest", .string, .identifier(auto: false))
            .field("expires_at", .datetime, .required)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(UsedNonce.schema).delete()
    }
}

extension Application {
    private struct LegacySignaturesKey: StorageKey { typealias Value = Bool }

    /// v1 signatures (no nonce, no host binding) from app versions ≤ 1.0.2.
    /// Turn off with `ACCEPT_LEGACY_SIGNATURES=false` once those are gone.
    var acceptsLegacySignatures: Bool {
        get { storage[LegacySignaturesKey.self] ?? true }
        set { storage[LegacySignaturesKey.self] = newValue }
    }
}

extension Sequence where Element == UInt8 {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
