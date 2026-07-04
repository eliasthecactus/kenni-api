import Vapor
import VaporAPNS
import APNSCore

/// Sends the two push types KENNI needs. The alert text is a localized key —
/// the phone renders it in the user's language; the server sends no names.
enum PushService {
    struct Payload: Codable {
        let requestID: String
        let kind: String // "request" | "response"
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
}
