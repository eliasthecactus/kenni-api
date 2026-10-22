import APNSCore
import Fluent
import Vapor
import VaporAPNS

extension APNSContainers.ID {
    static let production = APNSContainers.ID(string: "production")
    static let development = APNSContainers.ID(string: "development")
}

/// Sends verification, business and family notifications. Alert text uses
/// localization keys, so the server never needs to include names.
enum PushService {
    enum Kind: String {
        case request
        case response
        case businessRevoked
        case businessOutbound
        case alert

        var titleKey: String {
            switch self {
            case .request: "push.verify.request.title"
            case .response: "push.verify.response.title"
            case .businessRevoked: "push.business.revoked.title"
            case .businessOutbound: "push.business.outbound.title"
            case .alert: "push.family.alert.title"
            }
        }

        var bodyKey: String {
            switch self {
            case .request: "push.verify.request.body"
            case .response: "push.verify.response.body"
            case .businessRevoked: "push.business.revoked.body"
            case .businessOutbound: "push.business.outbound.body"
            case .alert: "push.family.alert.body"
            }
        }

        /// Notification category registered by the app (adds action buttons).
        var category: String? {
            switch self {
            case .request: "KENNI_VERIFY_REQUEST"
            case .businessOutbound: "KENNI_BUSINESS_OUTBOUND"
            default: nil
            }
        }

        var lifetime: TimeInterval {
            switch self {
            case .request, .response: 120
            case .businessOutbound: 300
            case .alert, .businessRevoked: 86_400
            }
        }
    }

    /// `requestID` is kept for app versions ≤ 1.0.2, which route on it.
    struct Payload: Codable {
        let kind: String
        let requestID: String?
        let id: String?
    }

    /// A push target: a personal registration or a business device.
    struct Target {
        let token: String
        let environment: String?
        /// Called with the working environment after a fallback, or nil when
        /// APNs says the token is dead.
        let update: @Sendable (String?) async throws -> Void
    }

    static func targets(for registrations: [DeviceRegistration], on db: any Database) -> [Target] {
        registrations.map { registration in
            Target(token: registration.apnsToken, environment: registration.apnsEnvironment) {
                environment in
                if let environment {
                    registration.apnsEnvironment = environment
                    try await registration.save(on: db)
                } else {
                    try await registration.delete(on: db)
                }
            }
        }
    }

    static func send(_ kind: Kind, id: String, to targets: [Target], on req: Request) async {
        for target in targets {
            await send(kind, id: id, to: target, on: req)
        }
    }

    static func send(_ kind: Kind, id: String, to target: Target, on req: Request) async {
        let primary = environmentID(target.environment)
        guard req.application.apns.containers.container(for: primary) != nil else {
            req.logger.info("push skipped (APNs not configured): \(kind.rawValue) \(id)")
            return
        }
        var alert = APNSAlertNotification(
            alert: .init(title: .localized(key: kind.titleKey, arguments: []),
                         body: .localized(key: kind.bodyKey, arguments: [])),
            expiration: .timeIntervalSince1970InSeconds(
                Int(Date().timeIntervalSince1970 + kind.lifetime)),
            priority: .immediately,
            topic: appTopic,
            payload: Payload(kind: kind.rawValue,
                             requestID: kind == .request || kind == .response ? id : nil,
                             id: id),
            sound: .default)
        alert.category = kind.category
        alert.interruptionLevel = kind == .alert || kind == .request ? .timeSensitive : nil

        let metrics = req.application.metrics
        do {
            try await req.application.apns.client(primary)
                .sendAlertNotification(alert, deviceToken: target.token)
            await metrics.increment(#"kenni_push_total{kind="\#(kind.rawValue)",result="ok"}"#)
        } catch let error as APNSError where error.reason == .badDeviceToken {
            // Usually a sandbox token sent to production (or the reverse).
            let fallback: APNSContainers.ID = primary == .production ? .development : .production
            guard req.application.apns.containers.container(for: fallback) != nil else {
                try? await target.update(nil)
                return
            }
            do {
                try await req.application.apns.client(fallback)
                    .sendAlertNotification(alert, deviceToken: target.token)
                try? await target.update(fallback.string)
                await metrics.increment(#"kenni_push_total{kind="\#(kind.rawValue)",result="ok"}"#)
            } catch {
                try? await target.update(nil)
                await metrics.increment(#"kenni_push_total{kind="\#(kind.rawValue)",result="dead"}"#)
            }
        } catch let error as APNSError where error.reason == .unregistered {
            // The app was deleted or notifications were turned off for good.
            try? await target.update(nil)
            await metrics.increment(#"kenni_push_total{kind="\#(kind.rawValue)",result="dead"}"#)
        } catch {
            req.logger.error("push failed: \(error)")
            await metrics.increment(#"kenni_push_total{kind="\#(kind.rawValue)",result="error"}"#)
        }
    }

    static var appTopic: String { Environment.get("APNS_TOPIC") ?? "ch.benavo.kenni" }

    static var defaultEnvironment: String {
        Environment.get("APNS_ENV") == "production" ? "production" : "development"
    }

    static func environmentID(_ environment: String?) -> APNSContainers.ID {
        (environment ?? defaultEnvironment) == "production" ? .production : .development
    }

    /// Mirrors the app's `CheckActivityAttributes.ContentState`.
    struct CheckActivityState: Codable {
        let phase: String
    }

    /// Flips the requester's lock-screen countdown to "answered" — the verdict
    /// itself is only ever decided in the app, after checking the signature.
    static func updateCheckActivity(token: String, environment: String?, phase: String,
                                    on req: Request) async {
        let container = environmentID(environment)
        guard req.application.apns.containers.container(for: container) != nil else { return }
        let notification = APNSLiveActivityNotification(
            expiration: .timeIntervalSince1970InSeconds(Int(Date().timeIntervalSince1970) + 120),
            priority: .immediately,
            appID: appTopic,
            contentState: CheckActivityState(phase: phase),
            event: .update,
            timestamp: Int(Date().timeIntervalSince1970))
        do {
            try await req.application.apns.client(container)
                .sendLiveActivityNotification(notification, deviceToken: token)
        } catch {
            req.logger.info("live activity update failed: \(error)")
        }
    }

    static func sendBusinessRevocation(to device: BusinessDevice, on req: Request) async {
        guard let token = device.apnsToken else { return }
        let target = Target(token: token, environment: device.apnsEnvironment) { environment in
            device.apnsEnvironment = environment
            if environment == nil { device.apnsToken = nil }
            try await device.save(on: req.db)
        }
        await send(.businessRevoked, id: device.id?.uuidString ?? "", to: target, on: req)
    }
}
