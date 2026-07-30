import Crypto
import Fluent
import Vapor

struct BusinessConfiguration: Sendable {
    let adminPSK: String?
    let businessSecret: String?

    static var environment: BusinessConfiguration {
        BusinessConfiguration(
            adminPSK: Environment.get("ADMIN_PSK").flatMap { $0.isEmpty ? nil : $0 },
            businessSecret: Environment.get("BUSINESS_TOKEN_SECRET")
                .flatMap { $0.isEmpty ? nil : $0 }
        )
    }

    var isAdminEnabled: Bool { adminPSK != nil && businessSecret != nil }

    func digest(context: String, value: String) -> String? {
        guard let businessSecret else { return nil }
        return Self.hmacHex(message: "kenni/\(context)/v1\n\(value)", secret: businessSecret)
    }

    func matchesAdminPSK(_ candidate: String) -> Bool {
        guard let adminPSK else { return false }
        let message = Data("kenni/admin-psk-check/v1".utf8)
        let expected = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: Data(adminPSK.utf8)))
        return HMAC<SHA256>.isValidAuthenticationCode(
            expected,
            authenticating: message,
            using: SymmetricKey(data: Data(candidate.utf8)))
    }

    static func hmacHex(message: String, secret: String) -> String {
        HMAC<SHA256>.authenticationCode(
            for: Data(message.utf8),
            using: SymmetricKey(data: Data(secret.utf8)))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

final class Business: Model, @unchecked Sendable {
    static let schema = "businesses"

    @ID(key: .id) var id: UUID?
    @Field(key: "name") var name: String
    @OptionalField(key: "logo_url") var logoURL: String?
    @Field(key: "address") var address: String
    @OptionalField(key: "website_url") var websiteURL: String?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(name: String, logoURL: String?, address: String, websiteURL: String?) {
        self.name = name
        self.logoURL = logoURL
        self.address = address
        self.websiteURL = websiteURL
    }
}

final class BusinessDeviceInvitation: Model, @unchecked Sendable {
    static let schema = "business_device_invitations"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessID: UUID
    @Field(key: "device_label") var deviceLabel: String
    @Field(key: "token_digest") var tokenDigest: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "claimed_at") var claimedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(id: UUID, businessID: UUID, deviceLabel: String, tokenDigest: String,
         expiresAt: Date) {
        self.id = id
        self.businessID = businessID
        self.deviceLabel = deviceLabel
        self.tokenDigest = tokenDigest
        self.expiresAt = expiresAt
    }
}

final class BusinessDevice: Model, @unchecked Sendable {
    static let schema = "business_devices"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessID: UUID
    @Field(key: "invitation_id") var invitationID: UUID
    @Field(key: "device_label") var deviceLabel: String
    @Field(key: "public_key") var publicKey: String
    @OptionalField(key: "apns_token") var apnsToken: String?
    @Timestamp(key: "enrolled_at", on: .create) var enrolledAt: Date?
    @OptionalField(key: "last_seen_at") var lastSeenAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?

    init() {}

    init(id: UUID, businessID: UUID, invitationID: UUID, deviceLabel: String,
         publicKey: String) {
        self.id = id
        self.businessID = businessID
        self.invitationID = invitationID
        self.deviceLabel = deviceLabel
        self.publicKey = publicKey
    }
}

final class BusinessConfirmation: Model, @unchecked Sendable {
    static let schema = "business_confirmations"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_device_id") var businessDeviceID: UUID
    @Field(key: "pin_digest") var pinDigest: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(id: UUID, businessDeviceID: UUID, pinDigest: String, expiresAt: Date) {
        self.id = id
        self.businessDeviceID = businessDeviceID
        self.pinDigest = pinDigest
        self.expiresAt = expiresAt
    }
}

struct CreateBusinesses: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(Business.schema)
            .id()
            .field("name", .string, .required)
            .field("logo_url", .string)
            .field("address", .string, .required)
            .field("website_url", .string)
            .field("created_at", .datetime)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(Business.schema).delete()
    }
}

struct RemoveBusinessPIN: AsyncMigration {
    func prepare(on database: any Database) async throws {
        // SQLite cannot drop a column from this UUID-primary-key table without
        // rebuilding it. Fresh SQLite installs never create the legacy column;
        // deployed PostgreSQL databases remove it here.
        guard !String(reflecting: type(of: database.configuration)).contains("SQLite")
        else { return }
        try await database.schema(Business.schema)
            .deleteField("pin_digest")
            .update()
    }

    func revert(on database: any Database) async throws {
        guard !String(reflecting: type(of: database.configuration)).contains("SQLite")
        else { return }
        try await database.schema(Business.schema)
            .field("pin_digest", .string)
            .update()
    }
}

struct CreateBusinessDevices: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(BusinessDeviceInvitation.schema)
            .id()
            .field("business_id", .uuid, .required,
                   .references(Business.schema, "id", onDelete: .cascade))
            .field("device_label", .string, .required)
            .field("token_digest", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("claimed_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "token_digest")
            .create()

        try await database.schema(BusinessDevice.schema)
            .id()
            .field("business_id", .uuid, .required,
                   .references(Business.schema, "id", onDelete: .cascade))
            .field("invitation_id", .uuid, .required,
                   .references(BusinessDeviceInvitation.schema, "id", onDelete: .restrict))
            .field("device_label", .string, .required)
            .field("public_key", .string, .required)
            .field("apns_token", .string)
            .field("enrolled_at", .datetime)
            .field("last_seen_at", .datetime)
            .field("revoked_at", .datetime)
            .unique(on: "invitation_id")
            .unique(on: "public_key")
            .create()

        try await database.schema(BusinessConfirmation.schema)
            .id()
            .field("business_device_id", .uuid, .required,
                   .references(BusinessDevice.schema, "id", onDelete: .cascade))
            .field("challenge_digest", .string, .required)
            .field("proof_digest", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "proof_digest")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(BusinessConfirmation.schema).delete()
        try await database.schema(BusinessDevice.schema).delete()
        try await database.schema(BusinessDeviceInvitation.schema).delete()
    }
}

struct ReplaceBusinessConfirmationChallengesWithPINs: AsyncMigration {
    func prepare(on database: any Database) async throws {
        // Confirmations live for only 90 seconds, so replacing this ephemeral table
        // is both safer and simpler than preserving obsolete challenge-response rows.
        try await database.schema(BusinessConfirmation.schema).delete()
        try await database.schema(BusinessConfirmation.schema)
            .id()
            .field("business_device_id", .uuid, .required,
                   .references(BusinessDevice.schema, "id", onDelete: .cascade))
            .field("pin_digest", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "business_device_id")
            .unique(on: "pin_digest")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(BusinessConfirmation.schema).delete()
        try await database.schema(BusinessConfirmation.schema)
            .id()
            .field("business_device_id", .uuid, .required,
                   .references(BusinessDevice.schema, "id", onDelete: .cascade))
            .field("challenge_digest", .string, .required)
            .field("proof_digest", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "proof_digest")
            .create()
    }
}

struct BusinessDTO: Content, Equatable {
    let id: UUID
    let name: String
    let logoURL: String?
    let address: String
    let websiteURL: String?

    init(_ business: Business) throws {
        id = try business.requireID()
        name = business.name
        logoURL = business.logoURL
        address = business.address
        websiteURL = business.websiteURL
    }
}

struct ClaimBusinessDeviceDTO: Content {
    let token: String
    let publicKey: String
    let signature: String
}

struct BusinessDeviceCredentialDTO: Content {
    let deviceID: UUID
    let deviceLabel: String
    let business: BusinessDTO
}

struct BusinessDeviceStatusDTO: Content {
    let deviceID: UUID
    let deviceLabel: String
    let status: String
    let revokedAt: Int?
    let business: BusinessDTO
}

struct BusinessDeviceAPNSDTO: Content {
    let apnsToken: String
}

struct BusinessPINDTO: Content {
    let pin: String
    let expiresAt: Int
}

struct VerifyBusinessPINDTO: Content {
    let pin: String
}

struct BusinessDeviceAuth {
    static func verify(_ req: Request, body: ByteBuffer?, allowRevoked: Bool = false) async throws -> BusinessDevice {
        guard let idRaw = req.headers.first(name: "X-Kenni-Business-Device"),
              let id = UUID(uuidString: idRaw),
              let timestampRaw = req.headers.first(name: "X-Kenni-Business-Timestamp"),
              let timestamp = Double(timestampRaw),
              abs(Date().timeIntervalSince1970 - timestamp) <= 300,
              let signatureRaw = req.headers.first(name: "X-Kenni-Business-Signature"),
              let signature = Data(base64URLEncoded: signatureRaw),
              let device = try await BusinessDevice.find(id, on: req.db),
              let keyData = Data(base64URLEncoded: device.publicKey),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
            throw Abort(.unauthorized, reason: "missing or invalid business device authentication")
        }
        let bodyString = body.map(String.init(buffer:)) ?? ""
        let message = Data("kenni/v1/business-device\n\(req.method.rawValue)\n\(req.url.path)\n\(timestampRaw)\n\(bodyString)".utf8)
        guard key.isValidSignature(signature, for: message) else {
            throw Abort(.unauthorized, reason: "invalid business device signature")
        }
        guard allowRevoked || device.revokedAt == nil else {
            throw Abort(.gone, reason: "business device revoked")
        }
        return device
    }

    static func enrollmentMessage(token: String, publicKey: String) -> Data {
        Data("kenni/v1/business-enrollment\n\(token)\n\(publicKey)".utf8)
    }
}


func randomBusinessToken() -> String {
    let key = SymmetricKey(size: .bits256)
    return key.withUnsafeBytes { Data($0).base64URLEncodedString() }
}

func randomBusinessPIN() -> String {
    String(format: "%06d", Int.random(in: 0..<1_000_000))
}

func timingSafeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    var difference = left.count ^ right.count
    for index in 0..<max(left.count, right.count) {
        difference |= Int(left.indices.contains(index) ? left[index] : 0)
            ^ Int(right.indices.contains(index) ? right[index] : 0)
    }
    return difference == 0
}
