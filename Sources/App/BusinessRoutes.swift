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
              let business = try await Business.find(invitation.businessID, on: req.db),
              business.status == .active else {
            throw Abort(.gone, reason: "invalid, expired, or already-used enrollment link")
        }

        let businessDTO = try await BusinessDTO.make(business, on: req)
        do {
            let credential = try await req.db.transaction { database in
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
                    deviceID: deviceID, deviceLabel: device.deviceLabel, business: businessDTO)
            }
            await Audit.record(req, actor: "device:\(credential.deviceID)",
                               action: "device.enrolled", businessID: credential.business.id,
                               target: credential.deviceLabel)
            return credential
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
        let status = device.revokedAt != nil ? "revoked"
            : business.status == .suspended ? "suspended" : "active"
        return BusinessDeviceStatusDTO(
            deviceID: try device.requireID(), deviceLabel: device.deviceLabel,
            status: status,
            revokedAt: device.revokedAt.map { Int($0.timeIntervalSince1970) },
            agentName: device.agentName,
            business: try await BusinessDTO.make(business, on: req))
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

    /// The representative using the device right now, shown to customers.
    businessDevices.put("agent") { req async throws -> HTTPStatus in
        let device = try await BusinessDeviceAuth.verify(req)
        let dto = try req.content.decode(BusinessAgentDTO.self)
        let name = dto.agentName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard name.count <= 80 else { throw Abort(.badRequest, reason: "name too long") }
        let previous = device.agentName
        device.agentName = name.isEmpty ? nil : name
        device.lastSeenAt = .now
        try await device.save(on: req.db)
        if previous != device.agentName {
            await Audit.record(req, actor: "device:\(try device.requireID())",
                               action: "device.agent_changed", businessID: device.businessID,
                               target: device.deviceLabel,
                               detail: device.agentName ?? "(none)")
        }
        return .ok
    }

    businessDevices.post("verification-pins") { req async throws -> BusinessPINDTO in
        guard businessConfiguration.businessSecret != nil else {
            throw Abort(.serviceUnavailable, reason: "business verification is not configured")
        }
        let (device, _) = try await BusinessDeviceAuth.verifyActive(req)
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
                await req.application.metrics.increment("kenni_business_pins_issued_total")
                return BusinessPINDTO(
                    pin: pin, expiresAt: Int(expiresAt.timeIntervalSince1970))
            } catch let error as any DatabaseError where error.isConstraintFailure {
                continue
            }
        }
        throw Abort(.serviceUnavailable, reason: "could not allocate a verification PIN")
    }

    /// Lets the representative see the moment their PIN is used.
    businessDevices.get("verification-pins", "current") { req async throws -> BusinessPINStatusDTO in
        let device = try await BusinessDeviceAuth.verify(req)
        guard let pin = try await BusinessConfirmation.query(on: req.db)
            .filter(\.$businessDeviceID == device.requireID()).first() else {
            return BusinessPINStatusDTO(status: "none", expiresAt: nil, redeemedAt: nil)
        }
        let status = pin.consumedAt != nil ? "redeemed"
            : pin.expiresAt < Date() ? "expired" : "pending"
        return BusinessPINStatusDTO(
            status: status, expiresAt: Int(pin.expiresAt.timeIntervalSince1970),
            redeemedAt: pin.consumedAt.map { Int($0.timeIntervalSince1970) })
    }

    // MARK: Outbound verification (the business contacts the customer)

    businessDevices.post("outbound-verifications") { req async throws -> Response in
        let (device, _) = try await BusinessDeviceAuth.verifyActive(req)
        let deviceID = try device.requireID()
        try await req.enforce(req.application.rateLimits.outbound, key: deviceID.uuidString)
        let dto = try req.content.decode(CreateOutboundVerificationDTO.self)
        guard let customerID = CustomerID.normalize(dto.customerID) else {
            throw Abort(.badRequest, reason: "malformed KENNI ID")
        }
        let registrations = try await DeviceRegistration.query(on: req.db)
            .filter(\.$customerID == customerID).all()
        // One key per KENNI ID in practice; refuse the (astronomically unlikely)
        // ambiguous case rather than guessing.
        let keys = Set(registrations.map(\.keyID))
        guard keys.count == 1, let customerKey = keys.first else {
            throw Abort(.notFound, reason: "customer is not reachable")
        }
        try await req.enforce(req.application.rateLimits.perRecipient, key: customerKey)
        let verification = OutboundVerification(businessDeviceID: deviceID,
                                                customerKeyID: customerKey)
        try await verification.create(on: req.db)
        let id = try verification.requireID()
        await Audit.record(req, actor: "device:\(deviceID)", action: "outbound.sent",
                           businessID: device.businessID, target: customerID)
        await PushService.send(.businessOutbound, id: id.uuidString,
                               to: PushService.targets(for: registrations, on: req.db), on: req)
        let body = OutboundVerificationStatusDTO(
            id: id, status: verification.publicStatus,
            expiresAt: Int(verification.expiresAt.timeIntervalSince1970), respondedAt: nil)
        let response = try await body.encodeResponse(for: req)
        response.status = .created
        return response
    }

    businessDevices.get("outbound-verifications", ":id") { req async throws -> OutboundVerificationStatusDTO in
        let device = try await BusinessDeviceAuth.verify(req)
        guard let id = req.parameters.get("id", as: UUID.self),
              let verification = try await OutboundVerification.find(id, on: req.db),
              verification.businessDeviceID == (try device.requireID()) else {
            throw Abort(.notFound)
        }
        return OutboundVerificationStatusDTO(
            id: id, status: verification.publicStatus,
            expiresAt: Int(verification.expiresAt.timeIntervalSince1970),
            respondedAt: verification.respondedAt.map { Int($0.timeIntervalSince1970) })
    }

    // MARK: Customer side

    v1.get("outbound-verifications", ":id") { req async throws -> OutboundVerificationDTO in
        let auth = try await KenniAuth.verify(req)
        guard let id = req.parameters.get("id", as: UUID.self),
              let verification = try await OutboundVerification.find(id, on: req.db),
              verification.customerKeyID == auth.keyID,
              let device = try await BusinessDevice.find(verification.businessDeviceID, on: req.db),
              let business = try await Business.find(device.businessID, on: req.db) else {
            throw Abort(.notFound)
        }
        // A revoked device or suspended business no longer vouches for anything.
        let status = device.revokedAt != nil || business.status != .active
            ? "expired" : verification.publicStatus
        return OutboundVerificationDTO(
            id: id, status: status,
            business: try await BusinessDTO.make(business, on: req),
            representative: RepresentativeDTO(deviceLabel: device.deviceLabel,
                                              agentName: device.agentName),
            createdAt: Int((verification.createdAt ?? .now).timeIntervalSince1970),
            expiresAt: Int(verification.expiresAt.timeIntervalSince1970))
    }

    v1.post("outbound-verifications", ":id", "response") { req async throws -> HTTPStatus in
        let auth = try await KenniAuth.verify(req)
        let dto = try req.content.decode(OutboundAnswerDTO.self)
        guard let answer = OutboundVerification.Status(rawValue: dto.answer), answer != .pending,
              let id = req.parameters.get("id", as: UUID.self),
              let verification = try await OutboundVerification.find(id, on: req.db),
              verification.customerKeyID == auth.keyID else {
            throw Abort(.notFound)
        }
        guard verification.publicStatus == "pending" else {
            throw Abort(.gone, reason: "verification expired or already answered")
        }
        verification.status = answer
        verification.respondedAt = .now
        try await verification.save(on: req.db)
        if let device = try await BusinessDevice.find(verification.businessDeviceID, on: req.db) {
            await Audit.record(req, actor: "customer", action: "outbound.\(answer.rawValue)",
                               businessID: device.businessID, target: device.deviceLabel)
        }
        return .ok
    }

    // MARK: Customer checks a PIN

    businessVerificationRoutes.post("verify") { req async throws -> BusinessVerificationDTO in
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
              let business = try await Business.find(device.businessID, on: req.db),
              business.status == .active else {
            await failures.record("global")
            await req.application.metrics.increment(
                #"kenni_business_pin_checks_total{result="rejected"}"#)
            throw Abort(.gone, reason: "verification PIN is invalid, expired, used, or revoked")
        }
        await req.application.metrics.increment(
            #"kenni_business_pin_checks_total{result="verified"}"#)
        return BusinessVerificationDTO(business: try await BusinessDTO.make(business, on: req),
                                       device: device)
    }

    // MARK: Hosted logos

    v1.get("businesses", ":id", "logo") { req async throws -> Response in
        guard let id = req.parameters.get("id", as: UUID.self),
              let logo = try await BusinessLogo.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        if req.headers.first(name: .ifNoneMatch) == "\"\(logo.sha256)\"" {
            return Response(status: .notModified)
        }
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: logo.contentType)
        headers.replaceOrAdd(name: .cacheControl, value: "public, max-age=86400")
        headers.replaceOrAdd(name: .eTag, value: "\"\(logo.sha256)\"")
        return Response(status: .ok, headers: headers, body: .init(data: logo.data))
    }
}
