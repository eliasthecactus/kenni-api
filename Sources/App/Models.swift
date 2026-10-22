import Crypto
import Fluent
import FluentSQL
import Vapor

/// One app installation that can receive pushes for a key. A key may have
/// several (iPhone + iPad); an installation belongs to one key at a time, so
/// switching identities on a phone moves its token to the new key.
final class DeviceRegistration: Model, @unchecked Sendable {
    static let schema = "device_registrations"

    @ID(key: .id) var id: UUID?
    @Field(key: "key_id") var keyID: String
    /// First 12 fingerprint characters — the "KENNI ID" a customer can read to a
    /// business for outbound verification.
    @Field(key: "customer_id") var customerID: String
    @Field(key: "apns_token") var apnsToken: String
    /// "production" | "development"; nil → the server's `APNS_ENV`.
    @OptionalField(key: "apns_environment") var apnsEnvironment: String?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}
    init(keyID: String, apnsToken: String, apnsEnvironment: String?) {
        self.keyID = keyID
        self.customerID = CustomerID.make(keyID: keyID) ?? ""
        self.apnsToken = apnsToken
        self.apnsEnvironment = apnsEnvironment
    }
}

/// A relayed call-verification request. Payloads are opaque signed envelopes —
/// all cryptography happens on the phones.
final class VerificationRequest: Model, @unchecked Sendable {
    static let schema = "verification_requests"

    @ID(custom: "request_id", generatedBy: .user) var id: String?
    @Field(key: "from_key_id") var fromKeyID: String
    @Field(key: "to_key_id") var toKeyID: String
    @Field(key: "request_payload") var requestPayload: String
    @OptionalField(key: "response_payload") var responsePayload: String?
    @Field(key: "expires_at") var expiresAt: Date
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(requestID: String, fromKeyID: String, toKeyID: String,
         requestPayload: String, ttl: TimeInterval = 90) {
        self.id = requestID
        self.fromKeyID = fromKeyID
        self.toKeyID = toKeyID
        self.requestPayload = requestPayload
        self.expiresAt = Date().addingTimeInterval(ttl)
    }
}

/// Optional encrypted contacts backup — an opaque blob the server cannot read.
final class BackupBlob: Model, @unchecked Sendable {
    static let schema = "backups"

    @ID(custom: "key_id", generatedBy: .user) var id: String?
    @Field(key: "blob") var blob: String
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}
    init(keyID: String, blob: String) {
        self.id = keyID
        self.blob = blob
    }
}

/// "Don't relay anything from this key to me." Requests from a blocked key get
/// the same 404 as an unregistered recipient, so the sender can't tell.
final class Block: Model, @unchecked Sendable {
    static let schema = "blocks"

    @ID(key: .id) var id: UUID?
    @Field(key: "blocker_key_id") var blockerKeyID: String
    @Field(key: "blocked_key_id") var blockedKeyID: String
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(blocker: String, blocked: String) {
        blockerKeyID = blocker
        blockedKeyID = blocked
    }

    static func exists(blocker: String, blocked: String, on db: any Database) async throws -> Bool {
        try await Block.query(on: db)
            .filter(\.$blockerKeyID == blocker)
            .filter(\.$blockedKeyID == blocked)
            .first() != nil
    }
}

/// Mirrors the app's fingerprint: base32(SHA-256(public key)), grouped in fours.
/// The first 12 characters double as the customer-facing KENNI ID.
enum CustomerID {
    static func make(keyID: String) -> String? {
        guard let key = Data(base64URLEncoded: keyID) else { return nil }
        return String(base32(Data(SHA256.hash(data: key)).prefix(8)).prefix(12))
    }

    /// "abcd-efgh ijkl" → "ABCDEFGHIJKL" (only the first 12 significant characters).
    static func normalize(_ raw: String) -> String? {
        let cleaned = raw.uppercased().filter { $0.isLetter || $0.isNumber }
        guard cleaned.count >= 12 else { return nil }
        return String(cleaned.prefix(12))
    }

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static func base32(_ data: Data) -> String {
        var result = ""
        var buffer = 0
        var bitsLeft = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                bitsLeft -= 5
                result.append(alphabet[(buffer >> bitsLeft) & 0x1F])
            }
        }
        if bitsLeft > 0 { result.append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]) }
        return result
    }
}

/// The original single-device table, kept only so `CreateTables` still runs on
/// fresh databases before `CreateDeviceRegistrations` migrates it away.
final class LegacyDevice: Model, @unchecked Sendable {
    static let schema = "devices"

    @ID(custom: "key_id", generatedBy: .user) var id: String?
    @Field(key: "apns_token") var apnsToken: String

    init() {}
}

struct CreateTables: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(LegacyDevice.schema)
            .field("key_id", .string, .identifier(auto: false))
            .field("apns_token", .string, .required)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()
        try await database.schema(VerificationRequest.schema)
            .field("request_id", .string, .identifier(auto: false))
            .field("from_key_id", .string, .required)
            .field("to_key_id", .string, .required)
            .field("request_payload", .string, .required)
            .field("response_payload", .string)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime)
            .create()
        try await database.schema(BackupBlob.schema)
            .field("key_id", .string, .identifier(auto: false))
            .field("blob", .string, .required)
            .field("updated_at", .datetime)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(LegacyDevice.schema).delete()
        try await database.schema(VerificationRequest.schema).delete()
        try await database.schema(BackupBlob.schema).delete()
    }
}

struct CreateDeviceRegistrations: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(DeviceRegistration.schema)
            .id()
            .field("key_id", .string, .required)
            .field("customer_id", .string, .required)
            .field("apns_token", .string, .required)
            .field("apns_environment", .string)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "apns_token")
            .create()

        // Same token under several keys (identity switches) → keep one row.
        var seenTokens = Set<String>()
        for legacy in try await LegacyDevice.query(on: database).all() {
            guard let keyID = legacy.id, seenTokens.insert(legacy.apnsToken).inserted else {
                continue
            }
            try await DeviceRegistration(keyID: keyID, apnsToken: legacy.apnsToken,
                                         apnsEnvironment: nil).create(on: database)
        }
        try await database.schema(LegacyDevice.schema).delete()

        try await database.schema(Block.schema)
            .id()
            .field("blocker_key_id", .string, .required)
            .field("blocked_key_id", .string, .required)
            .field("created_at", .datetime)
            .unique(on: "blocker_key_id", "blocked_key_id")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(Block.schema).delete()
        try await database.schema(LegacyDevice.schema)
            .field("key_id", .string, .identifier(auto: false))
            .field("apns_token", .string, .required)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()
        try await database.schema(DeviceRegistration.schema).delete()
    }
}

struct IndexDeviceRegistrations: AsyncMigration {
    func prepare(on database: any Database) async throws {
        guard let sql = database as? any SQLDatabase else { return }
        try await sql.raw(
            "CREATE INDEX IF NOT EXISTS device_registrations_key_id ON device_registrations (key_id)"
        ).run()
        try await sql.raw(
            "CREATE INDEX IF NOT EXISTS device_registrations_customer_id ON device_registrations (customer_id)"
        ).run()
    }

    func revert(on database: any Database) async throws {
        guard let sql = database as? any SQLDatabase else { return }
        try await sql.raw("DROP INDEX IF EXISTS device_registrations_key_id").run()
        try await sql.raw("DROP INDEX IF EXISTS device_registrations_customer_id").run()
    }
}
