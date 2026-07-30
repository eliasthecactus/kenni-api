import Crypto
import Vapor
import Fluent
import FluentSQL

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

func routes(_ app: Application, businessConfiguration: BusinessConfiguration,
            businessLookupLimiter: RateLimiterStore) throws {
    app.get("health") { _ in
        ["status": "ok"]
    }
    registerAdminPortal(on: app, configuration: businessConfiguration)

    let v1 = app.grouped("v1")
    let businessEnrollmentRoutes = v1.grouped("business-device-invitations")
        .grouped(RateLimitMiddleware(store: businessLookupLimiter))
    let businessVerificationRoutes = v1.grouped("business-verifications")
        .grouped(RateLimitMiddleware(store: businessLookupLimiter))

    // A one-time administrator invitation binds a freshly-generated device key
    // to a business. The invitation token is never retained in plaintext.
    businessEnrollmentRoutes.post("claim") { req async throws -> BusinessDeviceCredentialDTO in
        guard businessConfiguration.businessSecret != nil else {
            throw Abort(.serviceUnavailable, reason: "business verification is not configured")
        }
        let dto = try req.content.decode(ClaimBusinessDeviceDTO.self)
        guard dto.token.count <= 200,
              let invitationIDRaw = dto.token.split(separator: ".", maxSplits: 1).first,
              let invitationID = UUID(uuidString: String(invitationIDRaw)),
              let keyData = Data(base64URLEncoded: dto.publicKey), keyData.count == 32,
              let signature = Data(base64URLEncoded: dto.signature),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData),
              publicKey.isValidSignature(
                signature,
                for: BusinessDeviceAuth.enrollmentMessage(
                    token: dto.token, publicKey: dto.publicKey)),
              let expectedDigest = businessConfiguration.digest(
                context: "business-invitation", value: dto.token),
              let invitation = try await BusinessDeviceInvitation.find(invitationID, on: req.db),
              timingSafeEqual(invitation.tokenDigest, expectedDigest),
              invitation.claimedAt == nil, invitation.expiresAt > Date(),
              let business = try await Business.find(invitation.businessID, on: req.db) else {
            throw Abort(.gone, reason: "invalid, expired, or already-used enrollment link")
        }

        do {
            return try await req.db.transaction { database in
                guard let freshInvitation = try await BusinessDeviceInvitation.find(
                    invitationID, on: database),
                      freshInvitation.claimedAt == nil,
                      freshInvitation.expiresAt > Date() else {
                    throw Abort(.conflict, reason: "enrollment link already used")
                }
                let deviceID = UUID()
                let device = BusinessDevice(
                    id: deviceID, businessID: freshInvitation.businessID,
                    invitationID: invitationID, deviceLabel: freshInvitation.deviceLabel,
                    publicKey: dto.publicKey)
                try await device.create(on: database)
                freshInvitation.claimedAt = .now
                try await freshInvitation.save(on: database)
                return BusinessDeviceCredentialDTO(
                    deviceID: deviceID, deviceLabel: device.deviceLabel,
                    business: try BusinessDTO(business))
            }
        } catch {
            if let invitation = try? await BusinessDeviceInvitation.find(invitationID, on: req.db),
               invitation.claimedAt != nil {
                throw Abort(.conflict, reason: "enrollment link already used")
            }
            throw error
        }
    }

    let businessDevices = v1.grouped("business-devices")

    businessDevices.get("me") { req async throws -> BusinessDeviceStatusDTO in
        let device = try await BusinessDeviceAuth.verify(
            req, body: req.body.data, allowRevoked: true)
        guard let business = try await Business.find(device.businessID, on: req.db) else {
            throw Abort(.gone)
        }
        if device.revokedAt == nil {
            device.lastSeenAt = .now
            try await device.save(on: req.db)
        }
        return BusinessDeviceStatusDTO(
            deviceID: try device.requireID(), deviceLabel: device.deviceLabel,
            status: device.revokedAt == nil ? "active" : "revoked",
            revokedAt: device.revokedAt.map { Int($0.timeIntervalSince1970) },
            business: try BusinessDTO(business))
    }

    businessDevices.put("apns-token") { req async throws -> HTTPStatus in
        let device = try await BusinessDeviceAuth.verify(req, body: req.body.data)
        let dto = try req.content.decode(BusinessDeviceAPNSDTO.self)
        guard (32...512).contains(dto.apnsToken.count),
              dto.apnsToken.allSatisfy(\.isHexDigit) else {
            throw Abort(.badRequest, reason: "malformed device token")
        }
        device.apnsToken = dto.apnsToken
        device.lastSeenAt = .now
        try await device.save(on: req.db)
        return .ok
    }

    businessDevices.post("verification-pins") { req async throws -> BusinessPINDTO in
        guard businessConfiguration.businessSecret != nil else {
            throw Abort(.serviceUnavailable, reason: "business verification is not configured")
        }
        let device = try await BusinessDeviceAuth.verify(req, body: req.body.data)
        let deviceID = try device.requireID()

        for _ in 0..<10 {
            let pin = randomBusinessPIN()
            guard let pinDigest = businessConfiguration.digest(
                context: "business-pin", value: pin) else {
                throw Abort(.serviceUnavailable)
            }
            let expiresAt = Date().addingTimeInterval(90)
            do {
                try await req.db.transaction { database in
                    try await BusinessConfirmation.query(on: database)
                        .filter(\.$businessDeviceID == deviceID)
                        .delete()
                    try await BusinessConfirmation(
                        id: UUID(), businessDeviceID: deviceID,
                        pinDigest: pinDigest, expiresAt: expiresAt)
                        .create(on: database)
                    device.lastSeenAt = .now
                    try await device.save(on: database)
                }
                return BusinessPINDTO(
                    pin: pin, expiresAt: Int(expiresAt.timeIntervalSince1970))
            } catch let error as any DatabaseError where error.isConstraintFailure {
                continue
            }
        }
        throw Abort(.serviceUnavailable, reason: "could not allocate a verification PIN")
    }

    businessVerificationRoutes.post("verify") { req async throws -> BusinessDTO in
        guard businessConfiguration.businessSecret != nil else {
            throw Abort(.serviceUnavailable, reason: "business verification is not configured")
        }
        let dto = try req.content.decode(VerifyBusinessPINDTO.self)
        guard dto.pin.utf8.count == 6,
              dto.pin.utf8.allSatisfy({ (48...57).contains($0) }),
              let pinDigest = businessConfiguration.digest(
                context: "business-pin", value: dto.pin),
              let sql = req.db as? any SQLDatabase else {
            throw Abort(.badRequest, reason: "invalid verification PIN")
        }

        guard let row = try await sql.update(BusinessConfirmation.schema)
            .set("consumed_at", to: Date())
            .where("pin_digest", .equal, pinDigest)
            .where("expires_at", .greaterThan, Date())
            .where("consumed_at", .is, SQLLiteral.null)
            .returning("business_device_id")
            .first(),
              let deviceID = try? row.decode(
                column: "business_device_id", as: UUID.self),
              let device = try await BusinessDevice.find(deviceID, on: req.db),
              device.revokedAt == nil,
              let business = try await Business.find(device.businessID, on: req.db) else {
            throw Abort(.gone, reason: "verification PIN is invalid, expired, used, or revoked")
        }
        return try BusinessDTO(business)
    }

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
