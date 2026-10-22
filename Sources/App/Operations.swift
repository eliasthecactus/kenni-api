import Fluent
import FluentSQL
import Vapor

/// Health, metrics and logging plumbing.
func registerOperationalRoutes(on app: Application) {
    /// Liveness: the process answers.
    app.get("livez") { _ in ["status": "ok"] }

    /// Readiness: the database answers too. Used by the container healthcheck.
    app.get("health") { req async throws -> Response in
        do {
            if let sql = req.db as? any SQLDatabase {
                try await sql.raw("SELECT 1").run()
            }
            return try await ["status": "ok"].encodeResponse(for: req)
        } catch {
            req.logger.error("health check failed: \(error)")
            let response = try await ["status": "database unavailable"].encodeResponse(for: req)
            response.status = .serviceUnavailable
            return response
        }
    }

    /// Prometheus text format, only with `METRICS_TOKEN` set.
    app.get("metrics") { req async throws -> Response in
        guard let token = Environment.get("METRICS_TOKEN"), !token.isEmpty else {
            throw Abort(.notFound)
        }
        guard let bearer = req.headers.bearerAuthorization?.token,
              timingSafeEqual(bearer, token) else {
            throw Abort(.unauthorized)
        }
        var headers = HTTPHeaders()
        headers.contentType = HTTPMediaType(type: "text", subType: "plain",
                                            parameters: ["version": "0.0.4"])
        return Response(status: .ok, headers: headers,
                        body: .init(string: await req.application.metrics.render()))
    }
}

/// One JSON object per line (`LOG_FORMAT=json`) for log shippers.
struct JSONLogHandler: LogHandler {
    let label: String
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(level: Logger.Level, message: Logger.Message, metadata explicit: Logger.Metadata?,
             source: String, file: String, function: String, line: UInt) {
        var fields: [String: String] = [
            "ts": ISO8601DateFormatter().string(from: Date()),
            "level": level.rawValue,
            "logger": label,
            "msg": message.description,
        ]
        for (key, value) in metadata.merging(explicit ?? [:], uniquingKeysWith: { $1 }) {
            fields[key] = value.description
        }
        guard let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]),
              let line = String(data: data, encoding: .utf8) else { return }
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }
}
