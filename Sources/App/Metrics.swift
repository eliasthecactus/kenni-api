import Vapor

/// Minimal Prometheus-style counters. Exposed at `/metrics` only when
/// `METRICS_TOKEN` is set (scrape with `Authorization: Bearer <token>`).
actor MetricsStore {
    private var counters: [String: Int] = [:]

    /// `name` may carry labels: `kenni_push_total{kind="request",result="ok"}`.
    func increment(_ name: String, by value: Int = 1) {
        counters[name, default: 0] += value
    }

    func render() -> String {
        counters.keys.sorted().map { "\($0) \(counters[$0] ?? 0)" }.joined(separator: "\n") + "\n"
    }
}

extension Application {
    private struct MetricsKey: StorageKey { typealias Value = MetricsStore }

    var metrics: MetricsStore {
        if let existing = storage[MetricsKey.self] { return existing }
        let store = MetricsStore()
        storage[MetricsKey.self] = store
        return store
    }
}

/// Counts responses by status class so error spikes show up on a dashboard.
struct MetricsMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        do {
            let response = try await next.respond(to: request)
            await request.application.metrics.increment(
                #"kenni_http_responses_total{class="\#(response.status.code / 100)xx"}"#)
            return response
        } catch {
            let status = (error as? any AbortError)?.status.code ?? 500
            await request.application.metrics.increment(
                #"kenni_http_responses_total{class="\#(status / 100)xx"}"#)
            throw error
        }
    }
}
