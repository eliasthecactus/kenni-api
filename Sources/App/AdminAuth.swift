import Crypto
import Fluent
import Vapor

// MARK: - Sessions

/// A signed-in administrator. Super admins (shared key + TOTP) run the whole
/// directory; business admins (SSO) manage the devices of one business.
final class AdminSession: Model, @unchecked Sendable {
    static let schema = "admin_sessions"

    enum Role: String { case superAdmin = "super", business }

    @ID(key: .id) var id: UUID?
    @Field(key: "token_digest") var tokenDigest: String
    @Field(key: "csrf") var csrf: String
    @Field(key: "actor") var actor: String
    @Field(key: "role") var roleRaw: String
    @OptionalField(key: "business_id") var businessID: UUID?
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(tokenDigest: String, actor: String, role: Role, businessID: UUID?, ttl: TimeInterval) {
        self.tokenDigest = tokenDigest
        self.csrf = randomBusinessToken()
        self.actor = actor
        self.roleRaw = role.rawValue
        self.businessID = businessID
        self.expiresAt = Date().addingTimeInterval(ttl)
    }

    var role: Role { Role(rawValue: roleRaw) ?? .business }
    var isSuper: Bool { role == .superAdmin }

    /// Business admins may only touch their own business.
    func canManage(_ businessID: UUID) -> Bool {
        isSuper || self.businessID == businessID
    }
}

enum AdminSessions {
    static let cookieName = "kenni_admin"
    static let lifetime: TimeInterval = 8 * 3_600

    static func start(_ req: Request, actor: String, role: AdminSession.Role,
                      businessID: UUID?) async throws -> Response {
        let token = randomBusinessToken()
        try await AdminSession(tokenDigest: digest(token), actor: actor, role: role,
                               businessID: businessID, ttl: lifetime).create(on: req.db)
        await Audit.record(req, actor: actor, action: "admin.signed_in", businessID: businessID)
        let response = redirect(to: "/admin")
        response.headers.add(name: .setCookie, value: cookie(token, maxAge: Int(lifetime), req))
        return response
    }

    static func current(_ req: Request) async throws -> AdminSession? {
        guard let token = req.cookie(named: cookieName), token.count <= 100,
              let session = try await AdminSession.query(on: req.db)
                .filter(\.$tokenDigest == digest(token)).first(),
              session.revokedAt == nil, session.expiresAt > Date() else { return nil }
        if let businessID = session.businessID,
           let business = try await Business.find(businessID, on: req.db),
           business.status != .active || !business.isSSOConfigured {
            // A business admin's access ends with the business or its SSO setup.
            return nil
        }
        return session
    }

    static func end(_ req: Request) async throws -> Response {
        if let session = try await current(req) {
            session.revokedAt = .now
            try await session.save(on: req.db)
            await Audit.record(req, actor: session.actor, action: "admin.signed_out",
                               businessID: session.businessID)
        }
        let response = redirect(to: "/admin")
        response.headers.add(name: .setCookie, value: cookie("", maxAge: 0, req))
        return response
    }

    static func revokeAll(except keep: AdminSession, on db: any Database) async throws {
        try await AdminSession.query(on: db)
            .filter(\.$revokedAt == nil)
            .filter(\.$id != keep.requireID())
            .set(\.$revokedAt, to: .now)
            .update()
    }

    static func digest(_ token: String) -> String {
        SHA256.hash(data: Data("kenni/admin-session/v2\n\(token)".utf8)).hex
    }

    /// Lax (not Strict) so the session survives the redirect back from an SSO
    /// provider; every state change still needs the per-session CSRF token.
    private static func cookie(_ value: String, maxAge: Int, _ req: Request) -> String {
        "\(cookieName)=\(value); Path=/admin; Max-Age=\(maxAge); HttpOnly; SameSite=Lax"
            + (req.application.environment == .production ? "; Secure" : "")
    }
}

func redirect(to location: String) -> Response {
    let response = Response(status: .seeOther)
    response.headers.replaceOrAdd(name: .location, value: location)
    return response
}

extension Request {
    func cookie(named name: String) -> String? {
        headers.first(name: .cookie)?.split(separator: ";").lazy
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix("\(name)=") }
            .map { String($0.dropFirst(name.count + 1)) }
    }
}

// MARK: - TOTP (RFC 6238)

enum TOTP {
    static let period: TimeInterval = 30

    /// Accepts the current code and one step either side for clock drift. Each
    /// code works once.
    static func verify(_ code: String, secretBase32: String, on db: any Database,
                       now: Date = .init()) async throws -> Bool {
        let code = code.filter(\.isNumber)
        guard code.count == 6, let secret = base32Decode(secretBase32) else { return false }
        let counter = Int64(now.timeIntervalSince1970 / period)
        for step in [counter, counter - 1, counter + 1]
        where timingSafeEqual(generate(secret: secret, counter: step), code) {
            try await UsedNonce.consume(
                digest: SHA256.hash(data: Data("totp\n\(step)".utf8)).hex,
                expiresAt: now.addingTimeInterval(period * 3), on: db)
            return true
        }
        return false
    }

    static func generate(secret: Data, counter: Int64) -> String {
        var bigEndian = counter.bigEndian
        let message = withUnsafeBytes(of: &bigEndian) { Data($0) }
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(
            for: message, using: SymmetricKey(data: secret)))
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let value = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        return String(format: "%06d", value % 1_000_000)
    }

    static func base32Decode(_ string: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var buffer = 0
        var bits = 0
        var output = Data()
        for character in string.uppercased() where character != "=" && character != " " {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | index
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> bits) & 0xFF))
            }
        }
        return output.count >= 10 ? output : nil
    }
}

/// `swift run App admin-totp-secret` → a fresh secret for `ADMIN_TOTP_SECRET`.
struct AdminTOTPSecretCommand: AsyncCommand {
    struct Signature: CommandSignature {}
    var help: String { "Generates a TOTP secret for ADMIN_TOTP_SECRET" }

    func run(using context: CommandContext, signature: Signature) async throws {
        let bytes = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0.prefix(20)) }
        let secret = CustomerID.base32(bytes)
        context.console.print("ADMIN_TOTP_SECRET=\(secret)")
        context.console.print("otpauth://totp/KENNI%20Admin?secret=\(secret)&issuer=KENNI")
    }
}

// MARK: - Audit log

final class AuditEvent: Model, @unchecked Sendable {
    static let schema = "audit_events"

    @ID(key: .id) var id: UUID?
    @Field(key: "at") var at: Date
    @Field(key: "actor") var actor: String
    @Field(key: "action") var action: String
    @OptionalField(key: "business_id") var businessID: UUID?
    @OptionalField(key: "target") var target: String?
    @OptionalField(key: "detail") var detail: String?
    @OptionalField(key: "ip") var ip: String?

    init() {}
    init(actor: String, action: String, businessID: UUID?, target: String?, detail: String?,
         ip: String?) {
        self.at = .now
        self.actor = actor
        self.action = action
        self.businessID = businessID
        self.target = target
        self.detail = detail
        self.ip = ip
    }
}

enum Audit {
    /// Never fails the request: a lost audit row is logged instead.
    static func record(_ req: Request, actor: String, action: String, businessID: UUID? = nil,
                       target: String? = nil, detail: String? = nil) async {
        do {
            try await AuditEvent(actor: String(actor.prefix(200)), action: action,
                                 businessID: businessID, target: target.map { String($0.prefix(200)) },
                                 detail: detail.map { String($0.prefix(500)) },
                                 ip: req.clientIP).create(on: req.db)
        } catch {
            req.logger.error("audit write failed (\(action)): \(error)")
        }
    }
}

// MARK: - SSO (OpenID Connect, authorization code + PKCE)

final class OIDCLoginState: Model, @unchecked Sendable {
    static let schema = "oidc_login_states"

    @ID(custom: "state", generatedBy: .user) var id: String?
    @Field(key: "business_id") var businessID: UUID
    @Field(key: "nonce") var nonce: String
    @Field(key: "code_verifier") var codeVerifier: String
    @Field(key: "browser_digest") var browserDigest: String
    @Field(key: "expires_at") var expiresAt: Date

    init() {}
}

struct OIDCDiscovery: Content {
    let issuer: String
    let authorization_endpoint: String
    let token_endpoint: String
}

private struct OIDCTokenResponse: Content {
    let id_token: String
}

private struct IDTokenClaims: Decodable {
    let iss: String
    let aud: Audience
    let exp: Double
    let nonce: String?
    let email: String?
    let email_verified: Bool?
    let preferred_username: String?
    let azp: String?

    enum Audience: Decodable {
        case one(String)
        case many([String])

        init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let single = try? container.decode(String.self) { self = .one(single) }
            else { self = .many(try container.decode([String].self)) }
        }

        var values: [String] {
            switch self {
            case .one(let value): [value]
            case .many(let values): values
            }
        }
    }
}

enum SSO {
    static let browserCookie = "kenni_sso"

    static func redirectURI(_ configuration: BusinessConfiguration) -> String? {
        configuration.publicBaseURL.map { "\($0)/admin/sso/callback" }
    }

    static func discover(issuer: String, on req: Request) async throws -> OIDCDiscovery {
        let base = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        let response = try await req.client.get(URI(string: "\(base)/.well-known/openid-configuration"))
        guard response.status == .ok else {
            throw Abort(.badGateway, reason: "identity provider discovery failed")
        }
        let discovery = try response.content.decode(OIDCDiscovery.self)
        guard discovery.authorization_endpoint.hasPrefix("https://"),
              discovery.token_endpoint.hasPrefix("https://") else {
            throw Abort(.badGateway, reason: "identity provider endpoints must use HTTPS")
        }
        return discovery
    }

    /// Step 1: send the browser to the business's identity provider.
    static func begin(_ req: Request, business: Business,
                      configuration: BusinessConfiguration) async throws -> Response {
        guard business.status == .active, business.isSSOConfigured,
              let issuer = business.ssoIssuer, let clientID = business.ssoClientID,
              let redirectURI = redirectURI(configuration) else {
            throw Abort(.notFound)
        }
        let discovery = try await discover(issuer: issuer, on: req)
        let state = randomBusinessToken()
        let nonce = randomBusinessToken()
        let verifier = randomBusinessToken() + randomBusinessToken()
        let browser = randomBusinessToken()
        let login = OIDCLoginState()
        login.id = state
        login.businessID = try business.requireID()
        login.nonce = nonce
        login.codeVerifier = verifier
        login.browserDigest = SHA256.hash(data: Data(browser.utf8)).hex
        login.expiresAt = Date().addingTimeInterval(600)
        try await login.create(on: req.db)

        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        var components = URLComponents(string: discovery.authorization_endpoint)
        let existingItems = components?.queryItems ?? []
        components?.queryItems = existingItems + [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: clientID),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "scope", value: "openid email profile"),
            .init(name: "state", value: state),
            .init(name: "nonce", value: nonce),
            .init(name: "code_challenge", value: challenge),
            .init(name: "code_challenge_method", value: "S256"),
        ]
        guard let location = components?.url?.absoluteString else {
            throw Abort(.badGateway, reason: "invalid authorization endpoint")
        }
        let response = redirect(to: location)
        response.headers.add(
            name: .setCookie,
            value: "\(browserCookie)=\(browser); Path=/admin/sso; Max-Age=600; HttpOnly; SameSite=Lax"
                + (req.application.environment == .production ? "; Secure" : ""))
        return response
    }

    /// Step 2: the provider sends the browser back with a code.
    static func complete(_ req: Request, configuration: BusinessConfiguration) async throws -> (Business, String) {
        guard let state = req.query[String.self, at: "state"],
              let code = req.query[String.self, at: "code"],
              let login = try await OIDCLoginState.find(state, on: req.db) else {
            throw Abort(.badRequest, reason: "sign-in expired, please start again")
        }
        try await login.delete(on: req.db)
        guard login.expiresAt > Date(),
              let browser = req.cookie(named: browserCookie),
              timingSafeEqual(SHA256.hash(data: Data(browser.utf8)).hex, login.browserDigest),
              let business = try await Business.find(login.businessID, on: req.db),
              business.status == .active, business.isSSOConfigured,
              let issuer = business.ssoIssuer, let clientID = business.ssoClientID,
              let sealed = business.ssoClientSecretSealed,
              let clientSecret = configuration.unseal(sealed),
              let redirectURI = redirectURI(configuration) else {
            throw Abort(.badRequest, reason: "sign-in expired, please start again")
        }
        let discovery = try await discover(issuer: issuer, on: req)
        let tokenResponse = try await req.client.post(URI(string: discovery.token_endpoint)) { token in
            try token.content.encode([
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirectURI,
                "client_id": clientID,
                "client_secret": clientSecret,
                "code_verifier": login.codeVerifier,
            ], as: .urlEncodedForm)
        }
        guard tokenResponse.status == .ok,
              let idToken = try? tokenResponse.content.decode(OIDCTokenResponse.self).id_token else {
            throw Abort(.unauthorized, reason: "the identity provider refused the sign-in")
        }
        // The ID token came straight from the token endpoint over TLS, which
        // OpenID Connect Core §3.1.3.7 accepts instead of a signature check.
        // The claims are still validated in full.
        let parts = idToken.split(separator: ".")
        guard parts.count == 3, let payload = Data(base64URLEncoded: String(parts[1])),
              let claims = try? JSONDecoder().decode(IDTokenClaims.self, from: payload),
              claims.iss == discovery.issuer,
              claims.aud.values.contains(clientID),
              claims.aud.values.count == 1 || claims.azp == clientID,
              claims.exp > Date().timeIntervalSince1970 - 60,
              claims.nonce == login.nonce else {
            throw Abort(.unauthorized, reason: "invalid identity token")
        }
        guard let email = (claims.email ?? claims.preferred_username)?.lowercased(),
              claims.email_verified != false,
              business.allowsSSOEmail(email) else {
            await Audit.record(req, actor: claims.email ?? "unknown", action: "admin.sso_denied",
                               businessID: login.businessID)
            throw Abort(.forbidden, reason: "this account is not allowed to manage the business")
        }
        return (business, email)
    }
}

struct CreateAdministration: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(AdminSession.schema)
            .id()
            .field("token_digest", .string, .required)
            .field("csrf", .string, .required)
            .field("actor", .string, .required)
            .field("role", .string, .required)
            .field("business_id", .uuid, .references(Business.schema, "id", onDelete: .cascade))
            .field("expires_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "token_digest")
            .create()
        try await database.schema(AuditEvent.schema)
            .id()
            .field("at", .datetime, .required)
            .field("actor", .string, .required)
            .field("action", .string, .required)
            .field("business_id", .uuid)
            .field("target", .string)
            .field("detail", .string)
            .field("ip", .string)
            .create()
        try await database.schema(OIDCLoginState.schema)
            .field("state", .string, .identifier(auto: false))
            .field("business_id", .uuid, .required,
                   .references(Business.schema, "id", onDelete: .cascade))
            .field("nonce", .string, .required)
            .field("code_verifier", .string, .required)
            .field("browser_digest", .string, .required)
            .field("expires_at", .datetime, .required)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(OIDCLoginState.schema).delete()
        try await database.schema(AuditEvent.schema).delete()
        try await database.schema(AdminSession.schema).delete()
    }
}
