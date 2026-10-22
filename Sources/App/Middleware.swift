import Vapor

/// In-memory sliding-window rate limiter. A sensible baseline for a single
/// instance; behind several replicas put a shared limiter in front as well.
actor RateLimiterStore {
    private var hits: [String: [Date]] = [:]
    private let limit: Int
    private let window: TimeInterval

    init(limit: Int, window: TimeInterval) {
        self.limit = limit
        self.window = window
    }

    func allow(_ key: String, now: Date = .init()) -> Bool {
        let cutoff = now.addingTimeInterval(-window)
        var timestamps = (hits[key] ?? []).filter { $0 > cutoff }
        guard timestamps.count < limit else {
            hits[key] = timestamps
            return false
        }
        timestamps.append(now)
        hits[key] = timestamps
        return true
    }

    /// True while `key` is at or over the limit, without counting a new hit.
    func isExhausted(_ key: String, now: Date = .init()) -> Bool {
        let cutoff = now.addingTimeInterval(-window)
        return (hits[key] ?? []).filter { $0 > cutoff }.count >= limit
    }

    /// Records a hit without checking the limit (e.g. failed attempts).
    func record(_ key: String, now: Date = .init()) {
        let cutoff = now.addingTimeInterval(-window)
        hits[key] = (hits[key] ?? []).filter { $0 > cutoff } + [now]
    }

    /// Drops stale buckets so the map can't grow without bound.
    func sweep(now: Date = .init()) {
        let cutoff = now.addingTimeInterval(-window)
        for (key, times) in hits {
            let live = times.filter { $0 > cutoff }
            if live.isEmpty { hits[key] = nil } else { hits[key] = live }
        }
    }
}

/// Every limiter the API uses, configured once at boot.
struct RateLimits: Sendable {
    /// All traffic, per client IP.
    let perIP: RateLimiterStore
    /// Signed requests, per signing key — offices behind one NAT don't share it.
    let perKey: RateLimiterStore
    /// Unauthenticated business lookups (enrollment claim, PIN verify), per IP.
    let businessLookup: RateLimiterStore
    /// Wrong business PINs across all clients — caps distributed guessing.
    let pinFailures: RateLimiterStore
    /// Verification requests and alerts arriving at one recipient key.
    let perRecipient: RateLimiterStore
    /// Verification requests from one sender to one recipient.
    let perPair: RateLimiterStore
    /// Admin portal sign-in attempts, per IP.
    let adminLogin: RateLimiterStore
    /// Family alerts sent by one key.
    let alerts: RateLimiterStore
    /// Outbound business verifications sent by one business device.
    let outbound: RateLimiterStore

    static func fromEnvironment() -> RateLimits {
        func int(_ name: String, _ fallback: Int) -> Int {
            Environment.get(name).flatMap(Int.init) ?? fallback
        }
        return RateLimits(
            perIP: RateLimiterStore(limit: int("RATE_LIMIT", 300), window: 60),
            perKey: RateLimiterStore(limit: int("RATE_LIMIT_PER_KEY", 120), window: 60),
            businessLookup: RateLimiterStore(limit: 10, window: 60),
            pinFailures: RateLimiterStore(limit: int("PIN_FAILURE_BUDGET", 300), window: 600),
            perRecipient: RateLimiterStore(limit: 20, window: 600),
            perPair: RateLimiterStore(limit: 4, window: 60),
            adminLogin: RateLimiterStore(limit: 10, window: 900),
            alerts: RateLimiterStore(limit: 10, window: 3_600),
            outbound: RateLimiterStore(limit: 60, window: 3_600))
    }

    var all: [RateLimiterStore] {
        [perIP, perKey, businessLookup, pinFailures, perRecipient, perPair,
         adminLogin, alerts, outbound]
    }
}

extension Application {
    private struct RateLimitsKey: StorageKey { typealias Value = RateLimits }

    var rateLimits: RateLimits {
        get {
            guard let limits = storage[RateLimitsKey.self] else {
                fatalError("rate limits not configured")
            }
            return limits
        }
        set { storage[RateLimitsKey.self] = newValue }
    }
}

extension Request {
    /// Throws 429 when `store` has no room left for `key`.
    func enforce(_ store: RateLimiterStore, key: String) async throws {
        guard await store.allow(key) else {
            await application.metrics.increment("kenni_rate_limited_total")
            throw Abort(.tooManyRequests, reason: "slow down")
        }
    }
}

struct RateLimitMiddleware: AsyncMiddleware {
    let store: RateLimiterStore

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        // Health checks are unmetered so orchestrators can always probe.
        if request.url.path == "/health" || request.url.path == "/livez" {
            return try await next.respond(to: request)
        }
        try await request.enforce(store, key: request.clientIP)
        return try await next.respond(to: request)
    }
}

/// Conservative API defaults, with the minimum additional policy needed by the
/// server-rendered admin portal.
struct SecurityHeadersMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        response.headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.replaceOrAdd(name: "X-Frame-Options", value: "DENY")
        response.headers.replaceOrAdd(name: "Referrer-Policy", value: "no-referrer")
        let contentSecurityPolicy = request.url.path.hasPrefix("/admin")
            ? "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            : "default-src 'none'"
        response.headers.replaceOrAdd(name: "Content-Security-Policy",
                                      value: contentSecurityPolicy)
        return response
    }
}
