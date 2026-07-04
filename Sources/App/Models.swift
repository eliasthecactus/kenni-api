import Fluent
import Vapor

/// A registered device: public key ↔ APNs token. The key id is the base64url
/// Ed25519 public key — no accounts, no PII.
final class Device: Model, @unchecked Sendable {
    static let schema = "devices"

    @ID(custom: "key_id", generatedBy: .user) var id: String?
    @Field(key: "apns_token") var apnsToken: String
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}
    init(keyID: String, apnsToken: String) {
        self.id = keyID
        self.apnsToken = apnsToken
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

struct CreateTables: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(Device.schema)
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
        try await database.schema(Device.schema).delete()
        try await database.schema(VerificationRequest.schema).delete()
        try await database.schema(BackupBlob.schema).delete()
    }
}
