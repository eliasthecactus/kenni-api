import Vapor
import VaporAPNS
import APNSCore

/// Sends verification and business-device lifecycle notifications. Alert text
/// uses localization keys, so the server never needs to include names.
enum PushService {
    struct Payload: Codable {
        let requestID: String
        let kind: String // "request" | "response"
    }

    struct BusinessPayload: Codable {
        let kind: String
    }

    static func sendVerification(kind: String, requestID: String,
                                 toDeviceToken token: String, on req: Request) async {
        guard req.application.apns.containers.container() != nil else {
            req.logger.info("push skipped (APNs not configured): \(kind) \(requestID)")
            return
        }
        let alert = APNSAlertNotification(
            alert: .init(
                title: .localized(key: kind == "request" ? "push.verify.request.title"
                                                         : "push.verify.response.title",
                                  arguments: []),
                body: .localized(key: kind == "request" ? "push.verify.request.body"
                                                        : "push.verify.response.body",
                                 arguments: [])),
            expiration: .timeIntervalSince1970InSeconds(Int(Date().timeIntervalSince1970) + 120),
            priority: .immediately,
            topic: Environment.get("APNS_TOPIC") ?? "ch.benavo.kenni",
            payload: Payload(requestID: requestID, kind: kind),
            sound: .default)
        do {
            try await req.apns.client.sendAlertNotification(alert, deviceToken: token)
        } catch {
            req.logger.error("push failed: \(error)")
        }
    }

    static func sendBusinessRevocation(toDeviceToken token: String, on req: Request) async {
        guard req.application.apns.containers.container() != nil else {
            req.logger.info("push skipped (APNs not configured): business device revoked")
            return
        }
        let alert = APNSAlertNotification(
            alert: .init(
                title: .localized(key: "push.business.revoked.title", arguments: []),
                body: .localized(key: "push.business.revoked.body", arguments: [])),
            expiration: .timeIntervalSince1970InSeconds(
                Int(Date().timeIntervalSince1970) + 86_400),
            priority: .immediately,
            topic: Environment.get("APNS_TOPIC") ?? "ch.benavo.kenni",
            payload: BusinessPayload(kind: "businessRevoked"),
            sound: .default)
        do {
            try await req.apns.client.sendAlertNotification(alert, deviceToken: token)
        } catch {
            req.logger.error("business revocation push failed: \(error)")
        }
    }
}
