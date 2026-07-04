import Vapor

/// In-memory sliding-window rate limiter, keyed by client IP. A sensible baseline
/// for a single-instance Coolify deployment; put a real limiter (or Cloudflare)
/// in front if you scale horizontally.
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

    /// Drops stale buckets so the map can't grow without bound.
    func sweep(now: Date = .init()) {
        let cutoff = now.addingTimeInterval(-window)
        for (key, times) in hits {
            let live = times.filter { $0 > cutoff }
            if live.isEmpty { hits[key] = nil } else { hits[key] = live }
        }
    }
}

struct RateLimitMiddleware: AsyncMiddleware {
    let store: RateLimiterStore

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        // Health checks are unmetered so orchestrators can always probe.
        if request.url.path == "/health" {
            return try await next.respond(to: request)
        }
        let key = request.peerAddress?.ipAddress
            ?? request.remoteAddress?.ipAddress
            ?? "unknown"
        guard await store.allow(key) else {
            throw Abort(.tooManyRequests, reason: "slow down")
        }
        return try await next.respond(to: request)
    }
}

/// Conservative security headers. This is a JSON API with no browser surface,
/// but these are cheap and keep scanners quiet.
struct SecurityHeadersMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        response.headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.replaceOrAdd(name: "X-Frame-Options", value: "DENY")
        response.headers.replaceOrAdd(name: "Referrer-Policy", value: "no-referrer")
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'")
        return response
    }
}
