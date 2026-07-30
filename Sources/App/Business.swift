import Crypto
import Fluent
import Vapor

struct BusinessConfiguration: Sendable {
    let adminPSK: String?
    let pinSecret: String?

    static var environment: BusinessConfiguration {
        BusinessConfiguration(
            adminPSK: Environment.get("ADMIN_PSK").flatMap { $0.isEmpty ? nil : $0 },
            pinSecret: Environment.get("BUSINESS_PIN_SECRET").flatMap { $0.isEmpty ? nil : $0 }
        )
    }

    var isAdminEnabled: Bool { adminPSK != nil && pinSecret != nil }

    func pinDigest(_ pin: String) -> String? {
        guard let pinSecret else { return nil }
        return Self.hmacHex(message: "kenni/business-pin/v1\n\(pin)", secret: pinSecret)
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
    @Field(key: "pin_digest") var pinDigest: String
    @OptionalField(key: "logo_url") var logoURL: String?
    @Field(key: "address") var address: String
    @OptionalField(key: "website_url") var websiteURL: String?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(name: String, pinDigest: String, logoURL: String?, address: String,
         websiteURL: String?) {
        self.name = name
        self.pinDigest = pinDigest
        self.logoURL = logoURL
        self.address = address
        self.websiteURL = websiteURL
    }
}

struct CreateBusinesses: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(Business.schema)
            .id()
            .field("name", .string, .required)
            .field("pin_digest", .string, .required)
            .field("logo_url", .string)
            .field("address", .string, .required)
            .field("website_url", .string)
            .field("created_at", .datetime)
            .unique(on: "pin_digest")
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(Business.schema).delete()
    }
}

struct IdentifyBusinessDTO: Content {
    let pin: String
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

extension String {
    var normalizedBusinessPIN: String? {
        let normalized = filter(\.isNumber)
        guard normalized.count == 6, normalized.allSatisfy(\.isASCII) else { return nil }
        return normalized
    }
}
