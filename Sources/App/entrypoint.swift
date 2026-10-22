import Vapor

@main
enum Entrypoint {
    static func main() async throws {
        var env = try Environment.detect()
        if Environment.get("LOG_FORMAT") == "json" {
            let level = Environment.get("LOG_LEVEL").flatMap(Logger.Level.init(rawValue:)) ?? .info
            LoggingSystem.bootstrap { JSONLogHandler(label: $0, logLevel: level) }
        } else {
            try LoggingSystem.bootstrap(from: &env)
        }

        let app = try await Application.make(env)
        do {
            try await configure(app)
            try await app.execute()
        } catch {
            app.logger.report(error: error)
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }
}
