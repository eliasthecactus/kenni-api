import Vapor
import Fluent
import FluentPostgresDriver
import FluentSQLiteDriver
import VaporAPNS
import APNS
import APNSCore
import Crypto

public func configure(_ app: Application) async throws {
    // Cap request bodies well below any legitimate payload (largest is the 1 MB
    // backup blob) to blunt memory-exhaustion attempts.
    app.routes.defaultMaxBodySize = "2mb"

    // Global middleware: security headers + a per-IP rate limit.
    app.middleware.use(SecurityHeadersMiddleware())
    let rateLimiter = RateLimiterStore(
        limit: Int(Environment.get("RATE_LIMIT") ?? "120") ?? 120,
        window: 60)
    app.middleware.use(RateLimitMiddleware(store: rateLimiter))

    // MARK: Database — Postgres in deployment (Coolify), SQLite for local dev/tests.
    if app.environment == .testing {
        app.databases.use(.sqlite(.memory), as: .sqlite)
    } else if let databaseURL = Environment.get("DATABASE_URL") {
        try app.databases.use(.postgres(url: databaseURL), as: .psql)
    } else {
        app.databases.use(.sqlite(.file("kenni-dev.sqlite")), as: .sqlite)
    }

    app.migrations.add(CreateTables())
    try await app.autoMigrate()

    // MARK: APNs — configured only when keys are present, so local dev just logs.
    // APNS_KEY_P8 holds the key content (Coolify multiline env); APNS_KEY_PATH points
    // at a .p8 file for local development.
    let p8FromPath = Environment.get("APNS_KEY_PATH")
        .flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }
    if let p8 = Environment.get("APNS_KEY_P8") ?? p8FromPath,
       let keyID = Environment.get("APNS_KEY_ID"),
       let teamID = Environment.get("APNS_TEAM_ID") {
        let apnsConfig = APNSClientConfiguration(
            authenticationMethod: .jwt(
                privateKey: try .init(pemRepresentation: p8),
                keyIdentifier: keyID,
                teamIdentifier: teamID),
            environment: Environment.get("APNS_ENV") == "production" ? .production : .development)
        app.apns.containers.use(
            apnsConfig,
            eventLoopGroupProvider: .shared(app.eventLoopGroup),
            responseDecoder: JSONDecoder(),
            requestEncoder: JSONEncoder(),
            as: .default)
        app.logger.info("APNs configured (\(Environment.get("APNS_ENV") ?? "development"))")
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
            await rateLimiter.sweep()
        }
    }
    app.lifecycle.use(CancelOnShutdown(task: cleanupTask))

    app.asyncCommands.use(PushTestCommand(), as: "push-test")

    try routes(app)
}

struct CancelOnShutdown: LifecycleHandler {
    let task: Task<Void, Never>
    func shutdown(_ application: Application) { task.cancel() }
}

enum Cleanup {
    static func run(on db: any Database, logger: Logger) async throws {
        let now = Date()
        try await VerificationRequest.query(on: db).filter(\.$expiresAt < now).delete()
        logger.debug("cleanup pass done")
    }
}
