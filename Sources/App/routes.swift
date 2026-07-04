import Vapor
import Fluent

struct DeviceDTO: Content {
    let apnsToken: String
}

struct VerifyRequestDTO: Content {
    let requestID: String
    let to: String       // target key id (base64url pubkey)
    let payload: String  // opaque signed envelope, verified on the phones
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

func routes(_ app: Application) throws {
    app.get("health") { _ in
        ["status": "ok"]
    }

    let v1 = app.grouped("v1")

    // MARK: Devices

    v1.post("devices") { req async throws -> HTTPStatus in
        let auth = try KenniAuth.verify(req, body: req.body.data)
        let dto = try req.content.decode(DeviceDTO.self)
        // APNs device tokens are hex; reject anything malformed early.
        let token = dto.apnsToken
        guard (32...512).contains(token.count),
              token.allSatisfy({ $0.isHexDigit }) else {
            throw Abort(.badRequest, reason: "malformed device token")
        }
        if let device = try await Device.find(auth.keyID, on: req.db) {
            device.apnsToken = dto.apnsToken
            try await device.save(on: req.db)
        } else {
            try await Device(keyID: auth.keyID, apnsToken: dto.apnsToken).create(on: req.db)
        }
        return .ok
    }

    // Note: contact exchange is fully offline in the app (kenni:// links embed the
    // signed identity card), so there is deliberately no exchange endpoint here.

    // MARK: Call verification relay

    v1.post("verify", "requests") { req async throws -> HTTPStatus in
        let auth = try KenniAuth.verify(req, body: req.body.data)
        let dto = try req.content.decode(VerifyRequestDTO.self)
        guard dto.payload.count < 8192, dto.requestID.count <= 64 else {
            throw Abort(.payloadTooLarge)
        }
        guard try await VerificationRequest.find(dto.requestID, on: req.db) == nil else {
            throw Abort(.conflict, reason: "request id already used")
        }
        guard let target = try await Device.find(dto.to, on: req.db) else {
            throw Abort(.notFound, reason: "recipient is not reachable")
        }
        try await VerificationRequest(
            requestID: dto.requestID, fromKeyID: auth.keyID,
            toKeyID: dto.to, requestPayload: dto.payload
        ).create(on: req.db)
        await PushService.sendVerification(kind: "request", requestID: dto.requestID,
                                           toDeviceToken: target.apnsToken, on: req)
        return .created
    }

    v1.post("verify", "requests", ":id", "response") { req async throws -> HTTPStatus in
        let auth = try KenniAuth.verify(req, body: req.body.data)
        let id = req.parameters.get("id")!
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
        if let origin = try await Device.find(request.fromKeyID, on: req.db) {
            await PushService.sendVerification(kind: "response", requestID: id,
                                               toDeviceToken: origin.apnsToken, on: req)
        }
        return .ok
    }

    v1.get("verify", "requests", ":id") { req async throws -> VerifyStatusDTO in
        let auth = try KenniAuth.verify(req, body: req.body.data)
        let id = req.parameters.get("id")!
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
        let auth = try KenniAuth.verify(req, body: req.body.data)
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
        let auth = try KenniAuth.verify(req, body: req.body.data)
        guard let backup = try await BackupBlob.find(auth.keyID, on: req.db) else {
            throw Abort(.notFound)
        }
        return BackupDTO(blob: backup.blob)
    }
}
