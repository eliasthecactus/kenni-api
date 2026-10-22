import Crypto
import Fluent
import FluentSQL
import Vapor

func registerBusinessRoutes(on v1: any RoutesBuilder, app: Application,
                            businessConfiguration: BusinessConfiguration) {
    let businessEnrollmentRoutes = v1.grouped("business-device-invitations")
        .grouped(RateLimitMiddleware(store: app.rateLimits.businessLookup))
    let businessVerificationRoutes = v1.grouped("business-verifications")
        .grouped(RateLimitMiddleware(store: app.rateLimits.businessLookup))

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
        let device = try await BusinessDeviceAuth.verify(req, allowRevoked: true)
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
        let device = try await BusinessDeviceAuth.verify(req)
        let dto = try req.content.decode(BusinessDeviceAPNSDTO.self)
        guard (32...512).contains(dto.apnsToken.count),
              dto.apnsToken.allSatisfy(\.isHexDigit),
              dto.apnsEnvironment == nil
                || ["production", "development"].contains(dto.apnsEnvironment!) else {
            throw Abort(.badRequest, reason: "malformed device token")
        }
        device.apnsToken = dto.apnsToken.lowercased()
        device.apnsEnvironment = dto.apnsEnvironment
        device.lastSeenAt = .now
        try await device.save(on: req.db)
        return .ok
    }

    businessDevices.post("verification-pins") { req async throws -> BusinessPINDTO in
        guard businessConfiguration.businessSecret != nil else {
            throw Abort(.serviceUnavailable, reason: "business verification is not configured")
        }
        let device = try await BusinessDeviceAuth.verify(req)
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
        // Per-IP limits don't stop guessing spread over many addresses, so wrong
        // PINs also draw from one global budget.
        let failures = req.application.rateLimits.pinFailures
        guard await !failures.isExhausted("global") else {
            throw Abort(.tooManyRequests, reason: "too many wrong PINs, try again shortly")
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
            await failures.record("global")
            throw Abort(.gone, reason: "verification PIN is invalid, expired, used, or revoked")
        }
        return try BusinessDTO(business)
    }
}
