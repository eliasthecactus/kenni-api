import Vapor
import VaporAPNS
import APNSCore

/// Debugging aid: `swift run App push-test <device-token>` sends a test alert.
/// With a made-up token, a `BadDeviceToken` rejection from Apple still proves the
/// key, team id and connectivity are all correct.
struct PushTestCommand: AsyncCommand {
    struct Signature: CommandSignature {
        @Argument(name: "token", help: "APNs device token (hex)")
        var token: String
    }

    var help: String { "Sends a test push to the given APNs device token" }

    func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        guard app.apns.containers.container() != nil else {
            context.console.error("APNs is not configured — set APNS_KEY_PATH/APNS_KEY_P8, APNS_KEY_ID, APNS_TEAM_ID")
            return
        }
        struct Payload: Codable {
            let requestID: String
            let kind: String
        }
        let alert = APNSAlertNotification(
            alert: .init(title: .raw("KENNI"), body: .raw("Push test — everything works!")),
            expiration: .timeIntervalSince1970InSeconds(Int(Date().timeIntervalSince1970) + 120),
            priority: .immediately,
            topic: Environment.get("APNS_TOPIC") ?? "ch.benavo.kenni",
            payload: Payload(requestID: "push-test", kind: "test"),
            sound: .default)
        do {
            try await app.apns.client.sendAlertNotification(alert, deviceToken: signature.token)
            context.console.success("APNs accepted the push — delivered to the device.")
        } catch {
            context.console.error("APNs response: \(String(reflecting: error))")
        }
    }
}
