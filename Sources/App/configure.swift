import Vapor
import Fluent
import FluentPostgresDriver
import FluentSQLiteDriver
import VaporAPNS
import APNS
import APNSCore
import Crypto

public func configure(_ app: Application) async throws {
    try await configure(app, businessConfiguration: .environment)
}

func configure(_ app: Application, businessConfiguration: BusinessConfiguration) async throws {
    // Cap request bodies well below any legitimate payload (largest is the 1 MB
    // backup blob) to blunt memory-exhaustion attempts.
    app.routes.defaultMaxBodySize = "2mb"

    // Client addresses come from X-Forwarded-For only via trusted proxies
    // (TRUST_PROXY); see ClientIP.swift.
    app.clientIPResolver = .fromEnvironment(Environment.get("TRUST_PROXY"))
    app.acceptsLegacySignatures = Environment.get("ACCEPT_LEGACY_SIGNATURES") != "false"
    app.rateLimits = .fromEnvironment()
    app.businessConfiguration = businessConfiguration

    // Global middleware: metrics, security headers, per-IP rate limit.
    app.middleware.use(MetricsMiddleware())
    app.middleware.use(SecurityHeadersMiddleware())
    app.middleware.use(RateLimitMiddleware(store: app.rateLimits.perIP))

    // MARK: Database — Postgres in deployment (Coolify), SQLite for local dev/tests.
    if app.environment == .testing {
        app.databases.use(.sqlite(.memory), as: .sqlite)
    } else if let databaseURL = Environment.get("DATABASE_URL") {
        try app.databases.use(.postgres(url: databaseURL), as: .psql)
    } else {
        app.databases.use(.sqlite(.file("kenni-dev.sqlite")), as: .sqlite)
    }

    app.migrations.add(CreateTables())
    app.migrations.add(CreateBusinesses())
    app.migrations.add(RemoveBusinessPIN())
    app.migrations.add(CreateBusinessDevices())
    app.migrations.add(ReplaceBusinessConfirmationChallengesWithPINs())
    app.migrations.add(CreateUsedNonces())
    app.migrations.add(CreateDeviceRegistrations())
    app.migrations.add(IndexDeviceRegistrations())
    app.migrations.add(AddBusinessDeviceAPNSEnvironment())
    app.migrations.add(ExtendBusinessAdministration())
    app.migrations.add(CreateAdministration())
    app.migrations.add(CreateFamilyAlertsAndActivities())
    // Single instance: migrate on boot. Several replicas: set AUTO_MIGRATE=false
    // and run `App migrate --yes` once per deploy instead.
    if Environment.get("AUTO_MIGRATE") != "false" {
        try await app.autoMigrate()
    }

    // MARK: APNs — configured only when keys are present, so local dev just logs.
    // APNS_KEY_P8 holds the key content (Coolify multiline env); APNS_KEY_PATH points
    // at a .p8 file for local development.
    let p8FromPath = Environment.get("APNS_KEY_PATH")
        .flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }
    if let rawP8 = Environment.get("APNS_KEY_P8") ?? p8FromPath,
       let keyID = Environment.get("APNS_KEY_ID"),
       let teamID = Environment.get("APNS_TEAM_ID") {
        do {
            // Coolify (and most env-var UIs) mangle the multi-line PEM: newlines
            // collapse to spaces or literal "\n". Rebuild a canonical PEM so
            // CryptoKit can parse it however the newlines survived.
            let privateKey = try P256.Signing.PrivateKey(pemRepresentation: normalizePEM(rawP8))
            // Both endpoints: Xcode/ad-hoc builds hold sandbox tokens, TestFlight and
            // App Store builds production ones. Each registration says which.
            for (id, environment) in [(APNSContainers.ID.production, APNSEnvironment.production),
                                      (.development, .development)] {
                app.apns.containers.use(
                    APNSClientConfiguration(
                        authenticationMethod: .jwt(
                            privateKey: privateKey,
                            keyIdentifier: keyID,
                            teamIdentifier: teamID),
                        environment: environment),
                    eventLoopGroupProvider: .shared(app.eventLoopGroup),
                    responseDecoder: JSONDecoder(),
                    requestEncoder: JSONEncoder(),
                    as: id,
                    isDefault: PushService.environmentID(nil) == id)
            }
            app.logger.info("APNs configured (default for unlabeled tokens: \(PushService.defaultEnvironment))")
        } catch {
            // A malformed key must not take the whole server down — degrade to
            // log-only pushes, exactly like the unconfigured case.
            app.logger.error("APNs key failed to parse (\(error)) — pushes will only be logged")
        }
    } else {
        app.logger.warning("APNs not configured — pushes will only be logged")
    }

    // MARK: Expired-row cleanup every 10 minutes.
    let cleanupTask = Task { [weak app] in
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(600))
            // Cancellation makes the sleep return immediately — never touch the
            // database pool after shutdown has begun.
            guard !Task.isCancelled, let app else { return }
            try? await Cleanup.run(on: app.db, logger: app.logger)
            for limiter in app.rateLimits.all { await limiter.sweep() }
        }
    }
    app.lifecycle.use(CancelOnShutdown(task: cleanupTask))

    app.asyncCommands.use(PushTestCommand(), as: "push-test")
    app.asyncCommands.use(AdminTOTPSecretCommand(), as: "admin-totp-secret")

    if app.environment != .testing {
        // Hot-linked logos from before logos were hosted: copy them once.
        let importTask = Task { [weak app] in
            try? await Task.sleep(for: .seconds(5))
            guard !Task.isCancelled, let app else { return }
            await Logos.importLegacy(app: app)
        }
        app.lifecycle.use(CancelOnShutdown(task: importTask))
        if businessConfiguration.isSuperAdminEnabled, businessConfiguration.adminTOTPSecret == nil {
            app.logger.warning("ADMIN_TOTP_SECRET is not set — the admin sign-in has no second factor")
        }
    }

    try routes(app, businessConfiguration: businessConfiguration)
}

/// Reconstruct a canonical PKCS#8 PEM from a key whose newlines were flattened
/// by an env-var UI. Handles literal `\n`, CRLF, and fully-collapsed (spaces)
/// input by stripping the header/footer, removing all whitespace from the
/// base64 body, then re-wrapping at 64 chars.
func normalizePEM(_ raw: String) -> String {
    var s = raw.replacingOccurrences(of: "\\r\\n", with: "\n")
               .replacingOccurrences(of: "\\n", with: "\n")
               .replacingOccurrences(of: "\r", with: "\n")
    // If it already has real newlines and parses, we still normalize harmlessly.
    let header = "-----BEGIN PRIVATE KEY-----"
    let footer = "-----END PRIVATE KEY-----"
    s = s.replacingOccurrences(of: header, with: "")
         .replacingOccurrences(of: footer, with: "")
    let body = s.filter { !$0.isWhitespace }
    let wrapped = stride(from: 0, to: body.count, by: 64).map { start -> String in
        let a = body.index(body.startIndex, offsetBy: start)
        let b = body.index(a, offsetBy: min(64, body.count - start))
        return String(body[a..<b])
    }.joined(separator: "\n")
    return "\(header)\n\(wrapped)\n\(footer)"
}

struct CancelOnShutdown: LifecycleHandler {
    let task: Task<Void, Never>
    func shutdown(_ application: Application) { task.cancel() }
}

enum Cleanup {
    static func run(on db: any Database, logger: Logger) async throws {
        let now = Date()
        try await VerificationRequest.query(on: db).filter(\.$expiresAt < now).delete()
        try await UsedNonce.query(on: db).filter(\.$expiresAt < now).delete()
        try await FamilyAlert.query(on: db).filter(\.$expiresAt < now).delete()
        try await OIDCLoginState.query(on: db).filter(\.$expiresAt < now).delete()
        try await AdminSession.query(on: db).filter(\.$expiresAt < now).delete()
        // Outbound verifications stay a day so the business can still see the answer.
        try await OutboundVerification.query(on: db)
            .filter(\.$expiresAt < now.addingTimeInterval(-86_400)).delete()
        try await BusinessConfirmation.query(on: db).filter(\.$expiresAt < now).delete()
        try await BusinessDeviceInvitation.query(on: db)
            .filter(\.$expiresAt < now)
            .filter(\.$claimedAt == nil)
            .delete()
        logger.debug("cleanup pass done")
    }
}
