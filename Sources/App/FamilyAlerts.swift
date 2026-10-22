import Fluent
import Vapor

/// A family alert: "a check for one of our contacts just failed". The payload is
/// encrypted on the phone with the pairwise key, so the relay can't read whom it
/// is about.
final class FamilyAlert: Model, @unchecked Sendable {
    static let schema = "family_alerts"

    @ID(key: .id) var id: UUID?
    @Field(key: "from_key_id") var fromKeyID: String
    @Field(key: "to_key_id") var toKeyID: String
    @Field(key: "payload") var payload: String
    @Field(key: "expires_at") var expiresAt: Date
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(id: UUID, from: String, to: String, payload: String) {
        self.id = id
        fromKeyID = from
        toKeyID = to
        self.payload = payload
        expiresAt = Date().addingTimeInterval(86_400)
    }
}

struct SendFamilyAlertDTO: Content {
    let alertID: UUID
    let to: String
    let payload: String
}

struct FamilyAlertDTO: Content {
    let id: UUID
    let from: String
    let payload: String
    let createdAt: Int
}

func registerFamilyAlertRoutes(on v1: any RoutesBuilder) {
    v1.post("alerts") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(SendFamilyAlertDTO.self)
        guard dto.payload.count < 4096, dto.to.count <= 64 else { throw Abort(.payloadTooLarge) }
        let limits = req.application.rateLimits
        try await req.enforce(limits.alerts, key: auth.keyID)
        let targets = try await DeviceRegistration.query(on: req.db)
            .filter(\.$keyID == dto.to).all()
        guard !targets.isEmpty,
              try await !Block.exists(blocker: dto.to, blocked: auth.keyID, on: req.db) else {
            throw Abort(.notFound, reason: "recipient is not reachable")
        }
        try await req.enforce(limits.perRecipient, key: dto.to)
        guard try await FamilyAlert.find(dto.alertID, on: req.db) == nil else {
            throw Abort(.conflict, reason: "alert id already used")
        }
        try await FamilyAlert(id: dto.alertID, from: auth.keyID, to: dto.to,
                              payload: dto.payload).create(on: req.db)
        await PushService.send(.alert, id: dto.alertID.uuidString,
                               to: PushService.targets(for: targets, on: req.db), on: req)
        return .created
    }

    v1.get("alerts", ":id") { req async throws -> FamilyAlertDTO in
        let auth = try await KenniAuth.verify(req)
        guard let id = req.parameters.get("id", as: UUID.self),
              let alert = try await FamilyAlert.find(id, on: req.db),
              alert.toKeyID == auth.keyID, alert.expiresAt > Date() else {
            throw Abort(.notFound)
        }
        return FamilyAlertDTO(id: id, from: alert.fromKeyID, payload: alert.payload,
                              createdAt: Int((alert.createdAt ?? .now).timeIntervalSince1970))
    }
}

struct CreateFamilyAlertsAndActivities: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(FamilyAlert.schema)
            .id()
            .field("from_key_id", .string, .required)
            .field("to_key_id", .string, .required)
            .field("payload", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime)
            .create()
        try await database.schema(VerificationRequest.schema)
            .field("activity_token", .string)
            .update()
        try await database.schema(VerificationRequest.schema)
            .field("activity_environment", .string)
            .update()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(VerificationRequest.schema).deleteField("activity_environment").update()
        try await database.schema(VerificationRequest.schema).deleteField("activity_token").update()
        try await database.schema(FamilyAlert.schema).delete()
    }
}
