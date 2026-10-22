import Crypto
import Fluent
import FluentSQL
import Vapor

struct BusinessConfiguration: Sendable {
    let adminPSK: String?
    let businessSecret: String?
    /// Base32 TOTP secret; when set, the super-admin sign-in also needs a code.
    let adminTOTPSecret: String?
    /// e.g. `https://kenniapi.benavo.ch` — needed for SSO redirects and logo URLs.
    let publicBaseURL: String?

    init(adminPSK: String?, businessSecret: String?, adminTOTPSecret: String? = nil,
         publicBaseURL: String? = nil) {
        self.adminPSK = adminPSK
        self.businessSecret = businessSecret
        self.adminTOTPSecret = adminTOTPSecret
        self.publicBaseURL = publicBaseURL
    }

    static var environment: BusinessConfiguration {
        func value(_ name: String) -> String? {
            Environment.get(name).flatMap { $0.isEmpty ? nil : $0 }
        }
        return BusinessConfiguration(
            adminPSK: value("ADMIN_PSK"),
            businessSecret: value("BUSINESS_TOKEN_SECRET"),
            adminTOTPSecret: value("ADMIN_TOTP_SECRET"),
            publicBaseURL: value("PUBLIC_BASE_URL").map {
                $0.hasSuffix("/") ? String($0.dropLast()) : $0
            })
    }

    /// The portal needs the token secret; the super-admin sign-in also needs the PSK.
    var isAdminEnabled: Bool { businessSecret != nil }
    var isSuperAdminEnabled: Bool { adminPSK != nil && businessSecret != nil }

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

    // MARK: Secrets at rest (SSO client secrets)

    private var sealingKey: SymmetricKey? {
        guard let businessSecret else { return nil }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(businessSecret.utf8)),
            info: Data("kenni/sealed-secret/v1".utf8), outputByteCount: 32)
    }

    func seal(_ plaintext: String) -> String? {
        guard let sealingKey,
              let box = try? AES.GCM.seal(Data(plaintext.utf8), using: sealingKey),
              let combined = box.combined else { return nil }
        return combined.base64URLEncodedString()
    }

    func unseal(_ sealed: String) -> String? {
        guard let sealingKey, let data = Data(base64URLEncoded: sealed),
              let box = try? AES.GCM.SealedBox(combined: data),
              let plaintext = try? AES.GCM.open(box, using: sealingKey) else { return nil }
        return String(data: plaintext, encoding: .utf8)
    }
}

final class Business: Model, @unchecked Sendable {
    static let schema = "businesses"

    enum Status: String { case active, suspended }

    @ID(key: .id) var id: UUID?
    @Field(key: "name") var name: String
    /// Legacy hot-linked logo. Imported into `BusinessLogo` and then cleared.
    @OptionalField(key: "logo_url") var logoURL: String?
    @Field(key: "address") var address: String
    @OptionalField(key: "website_url") var websiteURL: String?
    @Field(key: "status") var statusRaw: String
    /// Short organisation id for the business admins' SSO sign-in URL.
    @OptionalField(key: "slug") var slug: String?
    @OptionalField(key: "sso_issuer") var ssoIssuer: String?
    @OptionalField(key: "sso_client_id") var ssoClientID: String?
    /// AES-GCM sealed with a key derived from `BUSINESS_TOKEN_SECRET`.
    @OptionalField(key: "sso_client_secret") var ssoClientSecretSealed: String?
    /// Comma-separated: exact addresses (`anna@acme.ch`) or domains (`@acme.ch`).
    @OptionalField(key: "sso_allowed_emails") var ssoAllowedEmails: String?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}

    init(name: String, address: String, websiteURL: String?) {
        self.name = name
        self.address = address
        self.websiteURL = websiteURL
        self.statusRaw = Status.active.rawValue
    }

    var status: Status {
        get { Status(rawValue: statusRaw) ?? .active }
        set { statusRaw = newValue.rawValue }
    }

    var isSSOConfigured: Bool {
        slug != nil && ssoIssuer != nil && ssoClientID != nil && ssoClientSecretSealed != nil
    }

    func allowsSSOEmail(_ email: String) -> Bool {
        let email = email.lowercased()
        let entries = (ssoAllowedEmails ?? "").split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
        return entries.contains { entry in
            entry.hasPrefix("@") ? email.hasSuffix(entry) : email == entry
        }
    }
}

/// Logos are stored here and served by the API, so the app never contacts a
/// third-party host and an approved logo can't be swapped behind our back.
final class BusinessLogo: Model, @unchecked Sendable {
    static let schema = "business_logos"

    @ID(custom: "business_id", generatedBy: .user) var id: UUID?
    @Field(key: "content_type") var contentType: String
    @Field(key: "data") var data: Data
    @Field(key: "sha256") var sha256: String
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}
    init(businessID: UUID, contentType: String, data: Data) {
        self.id = businessID
        self.contentType = contentType
        self.data = data
        self.sha256 = SHA256.hash(data: data).hex
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
    @OptionalField(key: "apns_environment") var apnsEnvironment: String?
    /// The representative currently using the device, shown to customers.
    @OptionalField(key: "agent_name") var agentName: String?
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

/// The business reaches out: a representative sends a signed-in confirmation
/// to a customer's KENNI ID; the customer's phone shows who is contacting them.
final class OutboundVerification: Model, @unchecked Sendable {
    static let schema = "outbound_verifications"

    enum Status: String { case pending, confirmed, rejected }

    @ID(key: .id) var id: UUID?
    @Field(key: "business_device_id") var businessDeviceID: UUID
    @Field(key: "customer_key_id") var customerKeyID: String
    @Field(key: "status") var statusRaw: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "responded_at") var respondedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(businessDeviceID: UUID, customerKeyID: String, ttl: TimeInterval = 300) {
        self.businessDeviceID = businessDeviceID
        self.customerKeyID = customerKeyID
        self.statusRaw = Status.pending.rawValue
        self.expiresAt = Date().addingTimeInterval(ttl)
    }

    var status: Status {
        get { Status(rawValue: statusRaw) ?? .pending }
        set { statusRaw = newValue.rawValue }
    }

    /// pending | confirmed | rejected | expired
    var publicStatus: String {
        status == .pending && expiresAt < Date() ? "expired" : status.rawValue
    }
}

// MARK: - Migrations

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
        // Older PostgreSQL installs have this legacy column; fresh installs do
        // not. The conditional drop also recovers a deployment where
        // CreateBusinesses completed before this migration previously failed.
        guard !String(reflecting: type(of: database.configuration)).contains("SQLite"),
              let sql = database as? any SQLDatabase else { return }
        try await sql.raw(
            "ALTER TABLE \"businesses\" DROP COLUMN IF EXISTS \"pin_digest\""
        ).run()
    }

    func revert(on database: any Database) async throws {
        guard !String(reflecting: type(of: database.configuration)).contains("SQLite"),
              let sql = database as? any SQLDatabase else { return }
        try await sql.raw(
            "ALTER TABLE \"businesses\" ADD COLUMN IF NOT EXISTS \"pin_digest\" TEXT"
        ).run()
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

struct AddBusinessDeviceAPNSEnvironment: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(BusinessDevice.schema)
            .field("apns_environment", .string)
            .update()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(BusinessDevice.schema)
            .deleteField("apns_environment")
            .update()
    }
}

/// Status, SSO, hosted logos, agent names and outbound verifications.
struct ExtendBusinessAdministration: AsyncMigration {
    func prepare(on database: any Database) async throws {
        // SQLite allows one column per ALTER TABLE, so add them one at a time.
        let businessFields: [(String, DatabaseSchema.DataType, [DatabaseSchema.FieldConstraint])] = [
            ("status", .string, [.required, .sql(.default("active"))]),
            ("slug", .string, []),
            ("sso_issuer", .string, []),
            ("sso_client_id", .string, []),
            ("sso_client_secret", .string, []),
            ("sso_allowed_emails", .string, []),
            ("updated_at", .datetime, []),
        ]
        for (name, type, constraints) in businessFields {
            try await database.schema(Business.schema)
                .field(.definition(name: .key(.init(stringLiteral: name)), dataType: type,
                                   constraints: constraints))
                .update()
        }
        if let sql = database as? any SQLDatabase {
            try await sql.raw(
                "CREATE UNIQUE INDEX IF NOT EXISTS businesses_slug ON businesses (slug)").run()
        }
        try await database.schema(BusinessDevice.schema)
            .field("agent_name", .string)
            .update()

        try await database.schema(BusinessLogo.schema)
            .field("business_id", .uuid, .identifier(auto: false),
                   .references(Business.schema, "id", onDelete: .cascade))
            .field("content_type", .string, .required)
            .field("data", .data, .required)
            .field("sha256", .string, .required)
            .field("updated_at", .datetime)
            .create()

        try await database.schema(OutboundVerification.schema)
            .id()
            .field("business_device_id", .uuid, .required,
                   .references(BusinessDevice.schema, "id", onDelete: .cascade))
            .field("customer_key_id", .string, .required)
            .field("status", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("responded_at", .datetime)
            .field("created_at", .datetime)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(OutboundVerification.schema).delete()
        try await database.schema(BusinessLogo.schema).delete()
        try await database.schema(BusinessDevice.schema).deleteField("agent_name").update()
        for name in ["status", "slug", "sso_issuer", "sso_client_id", "sso_client_secret",
                     "sso_allowed_emails", "updated_at"] {
            try await database.schema(Business.schema)
                .deleteField(.key(.init(stringLiteral: name))).update()
        }
    }
}

// MARK: - DTOs

struct BusinessDTO: Content, Equatable {
    let id: UUID
    let name: String
    let logoURL: String?
    let address: String
    let websiteURL: String?

    init(_ business: Business, logoURL: String?) throws {
        id = try business.requireID()
        name = business.name
        self.logoURL = logoURL
        address = business.address
        websiteURL = business.websiteURL
    }

    /// Loads the hosted logo's fingerprint so the URL changes with the image.
    static func make(_ business: Business, on req: Request) async throws -> BusinessDTO {
        let businessID = try business.requireID()
        let logo = try await BusinessLogo.find(businessID, on: req.db)
        let logoURL = logo.map {
            "\(req.publicBaseURL)/v1/businesses/\(businessID.uuidString)/logo?v=\($0.sha256.prefix(12))"
        }
        return try BusinessDTO(business, logoURL: logoURL)
    }
}

struct RepresentativeDTO: Content, Equatable {
    let deviceLabel: String
    let agentName: String?
}

/// What a customer sees after a PIN check. The business fields stay at the top
/// level so app versions ≤ 1.0.2 can still decode it as a plain business.
struct BusinessVerificationDTO: Content {
    let id: UUID
    let name: String
    let logoURL: String?
    let address: String
    let websiteURL: String?
    let representative: RepresentativeDTO
    let verifiedAt: Int

    init(business: BusinessDTO, device: BusinessDevice) {
        id = business.id
        name = business.name
        logoURL = business.logoURL
        address = business.address
        websiteURL = business.websiteURL
        representative = RepresentativeDTO(deviceLabel: device.deviceLabel,
                                           agentName: device.agentName)
        verifiedAt = Int(Date().timeIntervalSince1970)
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
    /// active | revoked | suspended
    let status: String
    let revokedAt: Int?
    let agentName: String?
    let business: BusinessDTO
}

struct BusinessDeviceAPNSDTO: Content {
    let apnsToken: String
    let apnsEnvironment: String?
}

struct BusinessAgentDTO: Content {
    let agentName: String?
}

struct BusinessPINDTO: Content {
    let pin: String
    let expiresAt: Int
}

struct BusinessPINStatusDTO: Content {
    /// none | pending | redeemed | expired
    let status: String
    let expiresAt: Int?
    let redeemedAt: Int?
}

struct VerifyBusinessPINDTO: Content {
    let pin: String
}

struct CreateOutboundVerificationDTO: Content {
    let customerID: String
}

struct OutboundVerificationStatusDTO: Content {
    let id: UUID
    /// pending | confirmed | rejected | expired
    let status: String
    let expiresAt: Int
    let respondedAt: Int?
}

/// The customer's view of an outbound verification.
struct OutboundVerificationDTO: Content {
    let id: UUID
    let status: String
    let business: BusinessDTO
    let representative: RepresentativeDTO
    let createdAt: Int
    let expiresAt: Int
}

struct OutboundAnswerDTO: Content {
    /// confirmed | rejected
    let answer: String
}

// MARK: - Device authentication

struct BusinessDeviceAuth {
    /// Same envelope as `KenniAuth` (see `SignedRequest`), with the context
    /// `business-device` and the device id as the signer.
    static func verify(_ req: Request, allowRevoked: Bool = false) async throws -> BusinessDevice {
        guard let idRaw = req.headers.first(name: "X-Kenni-Business-Device"),
              let id = UUID(uuidString: idRaw),
              let device = try await BusinessDevice.find(id, on: req.db),
              let keyData = Data(base64URLEncoded: device.publicKey),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
            throw Abort(.unauthorized, reason: "missing or invalid business device authentication")
        }
        try await SignedRequest.verify(
            req, context: "business-device", signer: idRaw.uppercased(), publicKey: key,
            timestampHeader: "X-Kenni-Business-Timestamp",
            signatureHeader: "X-Kenni-Business-Signature")
        try await req.enforce(req.application.rateLimits.perKey, key: "business:\(id)")
        guard allowRevoked || device.revokedAt == nil else {
            throw Abort(.gone, reason: "business device revoked")
        }
        return device
    }

    /// Like `verify`, and the business must be active (not suspended).
    static func verifyActive(_ req: Request) async throws -> (BusinessDevice, Business) {
        let device = try await verify(req)
        guard let business = try await Business.find(device.businessID, on: req.db) else {
            throw Abort(.gone, reason: "business removed")
        }
        guard business.status == .active else {
            throw Abort(.forbidden, reason: "business suspended")
        }
        return (device, business)
    }

    static func enrollmentMessage(token: String, publicKey: String) -> Data {
        Data("kenni/v1/business-enrollment\n\(token)\n\(publicKey)".utf8)
    }
}

extension Request {
    /// Absolute base for links handed to apps (logo URLs).
    var publicBaseURL: String {
        if let configured = application.businessConfiguration?.publicBaseURL { return configured }
        let host = headers.first(name: .host) ?? "localhost"
        return "https://\(host)"
    }
}

extension Application {
    private struct BusinessConfigurationKey: StorageKey { typealias Value = BusinessConfiguration }

    var businessConfiguration: BusinessConfiguration? {
        get { storage[BusinessConfigurationKey.self] }
        set { storage[BusinessConfigurationKey.self] = newValue }
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
