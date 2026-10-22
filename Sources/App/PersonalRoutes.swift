import Fluent
import Vapor

struct DeviceDTO: Content {
    let apnsToken: String
    /// "production" | "development" — which APNs endpoint this build's token
    /// belongs to. Optional for app versions ≤ 1.0.2.
    let apnsEnvironment: String?
}

struct UnregisterDeviceDTO: Content {
    let apnsToken: String?
}

struct VerifyRequestDTO: Content {
    let requestID: String
    let to: String       // target key id (base64url pubkey)
    let payload: String  // opaque signed envelope, verified on the phones
    /// Optional Live Activity push token of the requester's countdown.
    let activityToken: String?
    let activityEnvironment: String?
}

struct VerifyResponseDTO: Content {
    let payload: String
}

struct VerifyStatusDTO: Content {
    let requestID: String
    let status: String   // pending | answered | expired
    let requestPayload: String
    let responsePayload: String?
}

struct BackupDTO: Content {
    let blob: String
}

struct BlockDTO: Content {
    let key: String
}

/// At most this many installations per key; the oldest is dropped beyond it.
private let maxRegistrationsPerKey = 10

func registerPersonalRoutes(on v1: any RoutesBuilder) {
    // MARK: Devices

    v1.post("devices") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(DeviceDTO.self)
        // APNs device tokens are hex; reject anything malformed early.
        let token = dto.apnsToken.lowercased()
        guard (32...512).contains(token.count), token.allSatisfy(\.isHexDigit) else {
            throw Abort(.badRequest, reason: "malformed device token")
        }
        guard dto.apnsEnvironment == nil
                || ["production", "development"].contains(dto.apnsEnvironment!) else {
            throw Abort(.badRequest, reason: "unknown APNs environment")
        }
        if let existing = try await DeviceRegistration.query(on: req.db)
            .filter(\.$apnsToken == token).first() {
            existing.keyID = auth.keyID
            existing.customerID = CustomerID.make(keyID: auth.keyID) ?? ""
            existing.apnsEnvironment = dto.apnsEnvironment
            try await existing.save(on: req.db)
        } else {
            try await DeviceRegistration(keyID: auth.keyID, apnsToken: token,
                                         apnsEnvironment: dto.apnsEnvironment).create(on: req.db)
        }
        let registrations = try await DeviceRegistration.query(on: req.db)
            .filter(\.$keyID == auth.keyID)
            .sort(\.$updatedAt, .descending)
            .all()
        for stale in registrations.dropFirst(maxRegistrationsPerKey) {
            try await stale.delete(on: req.db)
        }
        return .ok
    }

    /// Stops pushes to one installation (`apnsToken`) or to all of this key's.
    v1.delete("devices") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try? req.content.decode(UnregisterDeviceDTO.self)
        var query = DeviceRegistration.query(on: req.db).filter(\.$keyID == auth.keyID)
        if let token = dto?.apnsToken?.lowercased() {
            query = query.filter(\.$apnsToken == token)
        }
        try await query.delete()
        return .noContent
    }

    /// Erases everything the relay holds for this key.
    v1.delete("me") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        try await req.db.transaction { db in
            try await DeviceRegistration.query(on: db).filter(\.$keyID == auth.keyID).delete()
            try await BackupBlob.query(on: db).filter(\.$id == auth.keyID).delete()
            try await Block.query(on: db).filter(\.$blockerKeyID == auth.keyID).delete()
            try await VerificationRequest.query(on: db).group(.or) {
                $0.filter(\.$fromKeyID == auth.keyID).filter(\.$toKeyID == auth.keyID)
            }.delete()
            try await FamilyAlert.query(on: db).group(.or) {
                $0.filter(\.$fromKeyID == auth.keyID).filter(\.$toKeyID == auth.keyID)
            }.delete()
        }
        return .noContent
    }

    // MARK: Blocks

    v1.post("blocks") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(BlockDTO.self)
        guard let keyData = Data(base64URLEncoded: dto.key), keyData.count == 32 else {
            throw Abort(.badRequest, reason: "malformed key")
        }
        if try await !Block.exists(blocker: auth.keyID, blocked: dto.key, on: req.db) {
            try await Block(blocker: auth.keyID, blocked: dto.key).create(on: req.db)
        }
        return .ok
    }

    v1.delete("blocks", ":key") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let blocked = try req.parameters.require("key")
        try await Block.query(on: req.db)
            .filter(\.$blockerKeyID == auth.keyID)
            .filter(\.$blockedKeyID == blocked)
            .delete()
        return .noContent
    }

    // Note: contact exchange is fully offline in the app (kenni:// links embed the
    // signed identity card), so there is deliberately no exchange endpoint here.

    // MARK: Call verification relay

    v1.post("verify", "requests") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(VerifyRequestDTO.self)
        guard dto.payload.count < 8192, dto.requestID.count <= 64, dto.to.count <= 64 else {
            throw Abort(.payloadTooLarge)
        }
        guard try await VerificationRequest.find(dto.requestID, on: req.db) == nil else {
            throw Abort(.conflict, reason: "request id already used")
        }
        let targets = try await DeviceRegistration.query(on: req.db)
            .filter(\.$keyID == dto.to).all()
        guard !targets.isEmpty,
              try await !Block.exists(blocker: dto.to, blocked: auth.keyID, on: req.db) else {
            throw Abort(.notFound, reason: "recipient is not reachable")
        }
        // Anyone holding a public key could otherwise flood its owner with pushes.
        let limits = req.application.rateLimits
        try await req.enforce(limits.perRecipient, key: dto.to)
        try await req.enforce(limits.perPair, key: "\(auth.keyID)>\(dto.to)")

        let request = VerificationRequest(
            requestID: dto.requestID, fromKeyID: auth.keyID,
            toKeyID: dto.to, requestPayload: dto.payload)
        if let token = dto.activityToken?.lowercased(), (32...512).contains(token.count),
           token.allSatisfy(\.isHexDigit) {
            request.activityToken = token
            request.activityEnvironment = dto.activityEnvironment
        }
        try await request.create(on: req.db)
        await req.application.metrics.increment("kenni_verifications_created_total")
        await PushService.send(.request, id: dto.requestID,
                               to: PushService.targets(for: targets, on: req.db), on: req)
        return .created
    }

    v1.post("verify", "requests", ":id", "response") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let id = try req.parameters.require("id")
        let dto = try req.content.decode(VerifyResponseDTO.self)
        guard dto.payload.count < 8192 else { throw Abort(.payloadTooLarge) }
        guard let request = try await VerificationRequest.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        guard request.toKeyID == auth.keyID else {
            throw Abort(.forbidden, reason: "only the recipient can answer")
        }
        guard request.expiresAt > Date(), request.responsePayload == nil else {
            throw Abort(.gone, reason: "request expired or already answered")
        }
        request.responsePayload = dto.payload
        try await request.save(on: req.db)
        let origins = try await DeviceRegistration.query(on: req.db)
            .filter(\.$keyID == request.fromKeyID).all()
        await PushService.send(.response, id: id,
                               to: PushService.targets(for: origins, on: req.db), on: req)
        if let token = request.activityToken {
            await PushService.updateCheckActivity(token: token,
                                                  environment: request.activityEnvironment,
                                                  phase: "answered", on: req)
        }
        return .ok
    }

    v1.get("verify", "requests", ":id") { req async throws -> VerifyStatusDTO in
        let auth = try await KenniAuth.verify(req)
        let id = try req.parameters.require("id")
        guard let request = try await VerificationRequest.find(id, on: req.db),
              request.fromKeyID == auth.keyID || request.toKeyID == auth.keyID else {
            throw Abort(.notFound)
        }
        let status: String
        if request.responsePayload != nil {
            status = "answered"
        } else if request.expiresAt < Date() {
            status = "expired"
        } else {
            status = "pending"
        }
        return VerifyStatusDTO(requestID: id, status: status,
                               requestPayload: request.requestPayload,
                               responsePayload: request.responsePayload)
    }

    // MARK: Encrypted backup (opt-in, opaque blob)

    v1.put("backup") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(BackupDTO.self)
        guard dto.blob.count < 1_048_576 else { throw Abort(.payloadTooLarge) }
        if let existing = try await BackupBlob.find(auth.keyID, on: req.db) {
            existing.blob = dto.blob
            try await existing.save(on: req.db)
        } else {
            try await BackupBlob(keyID: auth.keyID, blob: dto.blob).create(on: req.db)
        }
        return .ok
    }

    v1.get("backup") { req async throws -> BackupDTO in
        let auth = try await KenniAuth.verify(req)
        guard let backup = try await BackupBlob.find(auth.keyID, on: req.db) else {
            throw Abort(.notFound)
        }
        return BackupDTO(blob: backup.blob)
    }

    v1.delete("backup") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        try await BackupBlob.query(on: req.db).filter(\.$id == auth.keyID).delete()
        return .noContent
    }
}
