import XCTVapor
import Crypto
import Fluent
@testable import App

final class BusinessTests: XCTestCase {
    var app: Application!
    let configuration = BusinessConfiguration(
        adminPSK: "test-admin-key", businessSecret: "test-business-token-secret",
        adminTOTPSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        publicBaseURL: "https://kenniapi.test")

    override func setUp() async throws {
        app = try await Application.make(.testing)
        try await configure(app, businessConfiguration: configuration)
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        app = nil
    }

    // MARK: Helpers

    struct EnrolledDevice {
        let id: UUID
        let key: Curve25519.Signing.PrivateKey
    }

    func makeBusiness(_ name: String = "Acme AG") async throws -> Business {
        let business = Business(name: name, address: "Main Street 1", websiteURL: nil)
        try await business.create(on: app.db)
        return business
    }

    func enroll(_ business: Business, label: String = "Desk") async throws -> EnrolledDevice {
        let invitationID = UUID()
        let token = "\(invitationID.uuidString).\(randomBusinessToken())"
        try await BusinessDeviceInvitation(
            id: invitationID, businessID: business.requireID(), deviceLabel: label,
            tokenDigest: configuration.digest(context: "business-invitation", value: token)!,
            expiresAt: Date().addingTimeInterval(600)).create(on: app.db)
        let key = Curve25519.Signing.PrivateKey()
        let publicKey = key.publicKey.rawRepresentation.base64URLEncodedString()
        let signature = try key.signature(
            for: BusinessDeviceAuth.enrollmentMessage(token: token, publicKey: publicKey))
        let body = try JSONEncoder().encode(ClaimBusinessDeviceDTO(
            token: token, publicKey: publicKey, signature: signature.base64URLEncodedString()))
        var credential: BusinessDeviceCredentialDTO?
        try await app.test(.POST, "v1/business-device-invitations/claim", beforeRequest: { req in
            req.headers.contentType = .json
            req.body = ByteBuffer(data: body)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
            credential = try? res.content.decode(BusinessDeviceCredentialDTO.self)
        }
        return EnrolledDevice(id: try XCTUnwrap(credential).deviceID, key: key)
    }

    func business(_ method: HTTPMethod, _ path: String, body: String = "",
                  as device: EnrolledDevice) async throws -> (HTTPStatus, ByteBuffer) {
        var result: (HTTPStatus, ByteBuffer) = (.internalServerError, ByteBuffer())
        try await app.test(method, String(path.dropFirst()), beforeRequest: { req in
            let timestamp = String(Int(Date().timeIntervalSince1970))
            let nonce = AppTests.nonce()
            let message = SignedRequest.message(
                context: "business-device", host: AppTests.host, method: method.rawValue,
                path: path, timestamp: timestamp, nonce: nonce, body: body)
            req.headers.add(name: "Host", value: AppTests.host)
            req.headers.add(name: "X-Kenni-Business-Device", value: device.id.uuidString)
            req.headers.add(name: "X-Kenni-Business-Timestamp", value: timestamp)
            req.headers.add(name: "X-Kenni-Nonce", value: nonce)
            req.headers.add(name: "X-Kenni-Business-Signature",
                            value: try device.key.signature(for: message).base64URLEncodedString())
            req.headers.contentType = .json
            if !body.isEmpty { req.body = ByteBuffer(string: body) }
        }) { res async in
            result = (res.status, res.body)
        }
        return result
    }

    func personal(_ method: HTTPMethod, _ path: String, body: String = "",
                  key: Curve25519.Signing.PrivateKey) async throws -> (HTTPStatus, ByteBuffer) {
        var result: (HTTPStatus, ByteBuffer) = (.internalServerError, ByteBuffer())
        try await app.test(method, String(path.dropFirst()), beforeRequest: { req in
            let timestamp = String(Int(Date().timeIntervalSince1970))
            let nonce = AppTests.nonce()
            let message = SignedRequest.message(
                context: "api", host: AppTests.host, method: method.rawValue, path: path,
                timestamp: timestamp, nonce: nonce, body: body)
            req.headers.add(name: "Host", value: AppTests.host)
            req.headers.add(name: "X-Kenni-Id",
                            value: key.publicKey.rawRepresentation.base64URLEncodedString())
            req.headers.add(name: "X-Kenni-Timestamp", value: timestamp)
            req.headers.add(name: "X-Kenni-Nonce", value: nonce)
            req.headers.add(name: "X-Kenni-Signature",
                            value: try key.signature(for: message).base64URLEncodedString())
            req.headers.contentType = .json
            if !body.isEmpty { req.body = ByteBuffer(string: body) }
        }) { res async in
            result = (res.status, res.body)
        }
        return result
    }

    /// A signed-in admin cookie + CSRF token without going through the forms.
    func adminSession(role: AdminSession.Role, businessID: UUID? = nil) async throws -> (String, String) {
        let token = randomBusinessToken()
        let session = AdminSession(tokenDigest: AdminSessions.digest(token), actor: "tester",
                                   role: role, businessID: businessID, ttl: 600)
        try await session.create(on: app.db)
        return ("kenni_admin=\(token)", session.csrf)
    }

    func adminPost(_ path: String, form: String, cookie: String) async throws -> HTTPStatus {
        var status = HTTPStatus.internalServerError
        try await app.test(.POST, String(path.dropFirst()), beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
            req.headers.replaceOrAdd(name: "Content-Type", value: "application/x-www-form-urlencoded")
            req.body = ByteBuffer(string: form)
        }) { res async in status = res.status }
        return status
    }

    // MARK: Tests

    func testTOTPMatchesRFC6238() throws {
        // RFC 6238 appendix B, SHA-1 secret "12345678901234567890", T = 59 s.
        let secret = Data("12345678901234567890".utf8)
        XCTAssertEqual(TOTP.generate(secret: secret, counter: 1), "287082")
        XCTAssertEqual(TOTP.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), secret)
    }

    func testAdminLoginNeedsTOTPAndCodesWorkOnce() async throws {
        let secret = try XCTUnwrap(TOTP.base32Decode(configuration.adminTOTPSecret!))
        let code = TOTP.generate(secret: secret,
                                 counter: Int64(Date().timeIntervalSince1970 / 30))
        func login(_ totp: String) async throws -> HTTPStatus {
            var status = HTTPStatus.internalServerError
            try await app.test(.POST, "admin/login", beforeRequest: { req in
                req.headers.replaceOrAdd(name: "Content-Type",
                                         value: "application/x-www-form-urlencoded")
                req.body = ByteBuffer(string: "psk=test-admin-key&totp=\(totp)")
            }) { res async in status = res.status }
            return status
        }
        let wrong = code == "000000" ? "111111" : "000000"
        let rejected = try await login(wrong)
        XCTAssertEqual(rejected, .forbidden)
        let accepted = try await login(code)
        XCTAssertEqual(accepted, .seeOther)
        let replayed = try await login(code)
        XCTAssertEqual(replayed, .forbidden)
    }

    func testLogoutRevokesTheSession() async throws {
        let (cookie, csrf) = try await adminSession(role: .superAdmin)
        try await app.test(.GET, "admin", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }) { res async in XCTAssertEqual(res.status, .ok) }
        _ = try await adminPost("/admin/logout", form: "csrf=\(csrf)", cookie: cookie)
        try await app.test(.GET, "admin", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: cookie)
        }) { res async in XCTAssertEqual(res.status, .unauthorized) }
    }

    func testAgentNamePINStatusAndSuspension() async throws {
        let acme = try await makeBusiness()
        let device = try await enroll(acme)

        let (agentStatus, _) = try await business(.PUT, "/v1/business-devices/agent",
                                                  body: #"{"agentName":"Anna Meier"}"#, as: device)
        XCTAssertEqual(agentStatus, .ok)

        let (issued, pinBody) = try await business(.POST, "/v1/business-devices/verification-pins",
                                                   as: device)
        XCTAssertEqual(issued, .ok)
        let pin = try JSONDecoder().decode(BusinessPINDTO.self, from: pinBody).pin

        var (_, statusBody) = try await business(.GET, "/v1/business-devices/verification-pins/current",
                                                 as: device)
        XCTAssertEqual(try JSONDecoder().decode(BusinessPINStatusDTO.self, from: statusBody).status,
                       "pending")

        try await app.test(.POST, "v1/business-verifications/verify", beforeRequest: { req in
            req.headers.contentType = .json
            req.body = ByteBuffer(string: #"{"pin":"\#(pin)"}"#)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
            let result = try? res.content.decode(BusinessVerificationDTO.self)
            XCTAssertEqual(result?.representative.agentName, "Anna Meier")
            XCTAssertEqual(result?.representative.deviceLabel, "Desk")
        }

        (_, statusBody) = try await business(.GET, "/v1/business-devices/verification-pins/current",
                                             as: device)
        XCTAssertEqual(try JSONDecoder().decode(BusinessPINStatusDTO.self, from: statusBody).status,
                       "redeemed")

        // Suspended: no new PINs, and /me says so without revoking the device.
        let (cookie, csrf) = try await adminSession(role: .superAdmin)
        let suspended = try await adminPost("/admin/businesses/\(try acme.requireID())/status",
                                            form: "csrf=\(csrf)&status=suspended", cookie: cookie)
        XCTAssertEqual(suspended, .seeOther)
        let (refused, _) = try await business(.POST, "/v1/business-devices/verification-pins",
                                              as: device)
        XCTAssertEqual(refused, .forbidden)
        let (_, meBody) = try await business(.GET, "/v1/business-devices/me", as: device)
        XCTAssertEqual(try JSONDecoder().decode(BusinessDeviceStatusDTO.self, from: meBody).status,
                       "suspended")

        let events = try await AuditEvent.query(on: app.db).all().map(\.action)
        XCTAssertTrue(events.contains("device.agent_changed"))
        XCTAssertTrue(events.contains("business.suspended"))
    }

    func testOutboundVerification() async throws {
        let acme = try await makeBusiness()
        let device = try await enroll(acme)
        let customer = Curve25519.Signing.PrivateKey()
        let customerKeyID = customer.publicKey.rawRepresentation.base64URLEncodedString()
        let (registered, _) = try await personal(
            .POST, "/v1/devices", body: #"{"apnsToken":"\#(String(repeating: "d", count: 64))"}"#,
            key: customer)
        XCTAssertEqual(registered, .ok)
        let kenniID = try XCTUnwrap(CustomerID.make(keyID: customerKeyID))
        let spoken = stride(from: 0, to: 12, by: 4).map {
            String(Array(kenniID)[$0..<$0 + 4]).lowercased()
        }.joined(separator: "-")

        let (unknown, _) = try await business(
            .POST, "/v1/business-devices/outbound-verifications",
            body: #"{"customerID":"AAAA-BBBB-CCCC"}"#, as: device)
        XCTAssertEqual(unknown, .notFound)

        let (created, createdBody) = try await business(
            .POST, "/v1/business-devices/outbound-verifications",
            body: #"{"customerID":"\#(spoken)"}"#, as: device)
        XCTAssertEqual(created, .created)
        let id = try JSONDecoder().decode(OutboundVerificationStatusDTO.self, from: createdBody).id

        // Someone else can't read or answer it.
        let stranger = Curve25519.Signing.PrivateKey()
        let (hidden, _) = try await personal(.GET, "/v1/outbound-verifications/\(id)", key: stranger)
        XCTAssertEqual(hidden, .notFound)

        let (seen, seenBody) = try await personal(.GET, "/v1/outbound-verifications/\(id)",
                                                  key: customer)
        XCTAssertEqual(seen, .ok)
        let view = try JSONDecoder().decode(OutboundVerificationDTO.self, from: seenBody)
        XCTAssertEqual(view.business.name, "Acme AG")
        XCTAssertEqual(view.status, "pending")

        let (answered, _) = try await personal(
            .POST, "/v1/outbound-verifications/\(id)/response",
            body: #"{"answer":"confirmed"}"#, key: customer)
        XCTAssertEqual(answered, .ok)
        let (again, _) = try await personal(
            .POST, "/v1/outbound-verifications/\(id)/response",
            body: #"{"answer":"rejected"}"#, key: customer)
        XCTAssertEqual(again, .gone)

        let (_, statusBody) = try await business(
            .GET, "/v1/business-devices/outbound-verifications/\(id)", as: device)
        XCTAssertEqual(
            try JSONDecoder().decode(OutboundVerificationStatusDTO.self, from: statusBody).status,
            "confirmed")
    }

    func testBusinessAdminsOnlyManageTheirOwnBusiness() async throws {
        let acme = try await makeBusiness("Acme AG")
        let other = try await makeBusiness("Other AG")
        let otherDevice = try await enroll(other)
        let (cookie, csrf) = try await adminSession(role: .business,
                                                    businessID: try acme.requireID())
        // Business sessions need an active business with SSO configured.
        acme.slug = "acme"
        acme.ssoIssuer = "https://idp.test"
        acme.ssoClientID = "client"
        acme.ssoClientSecretSealed = configuration.seal("secret")
        try await acme.save(on: app.db)

        let foreign = try await adminPost(
            "/admin/businesses/\(try other.requireID())/devices/\(otherDevice.id)/revoke",
            form: "csrf=\(csrf)", cookie: cookie)
        XCTAssertEqual(foreign, .notFound)
        let forbidden = try await adminPost("/admin/businesses/\(try acme.requireID())/status",
                                            form: "csrf=\(csrf)&status=suspended", cookie: cookie)
        XCTAssertEqual(forbidden, .forbidden)
        let ownInvite = try await adminPost("/admin/businesses/\(try acme.requireID())/devices",
                                            form: "csrf=\(csrf)&deviceLabel=Phone", cookie: cookie)
        XCTAssertEqual(ownInvite, .created)
        let missingCSRF = try await adminPost("/admin/businesses/\(try acme.requireID())/devices",
                                              form: "csrf=nope&deviceLabel=Phone", cookie: cookie)
        XCTAssertEqual(missingCSRF, .forbidden)
    }

    func testSSOAllowList() {
        let business = Business(name: "Acme", address: "x", websiteURL: nil)
        business.ssoAllowedEmails = "it@acme.ch, @ops.acme.ch"
        XCTAssertTrue(business.allowsSSOEmail("IT@acme.ch"))
        XCTAssertTrue(business.allowsSSOEmail("anna@ops.acme.ch"))
        XCTAssertFalse(business.allowsSSOEmail("anna@acme.ch"))
        XCTAssertFalse(business.allowsSSOEmail("it@acme.ch.evil.com"))
    }

    func testSealedSecretsRoundTrip() {
        let sealed = try? XCTUnwrap(configuration.seal("client-secret"))
        XCTAssertNotEqual(sealed, "client-secret")
        XCTAssertEqual(sealed.flatMap(configuration.unseal), "client-secret")
    }

    func testLogoUploadIsServedAndBusinessCanBeDeleted() async throws {
        let acme = try await makeBusiness()
        let id = try acme.requireID()
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3])
        try await BusinessLogo(businessID: id, contentType: "image/png", data: png).create(on: app.db)
        try await app.test(.GET, "v1/businesses/\(id)/logo") { res async in
            XCTAssertEqual(res.status, .ok)
            XCTAssertEqual(res.headers.contentType?.description, "image/png")
        }
        XCTAssertNil(Logos.validate(Data("<svg/>".utf8)))

        _ = try await enroll(acme)
        let (cookie, csrf) = try await adminSession(role: .superAdmin)
        let mismatch = try await adminPost("/admin/businesses/\(id)/delete",
                                           form: "csrf=\(csrf)&confirmName=Acme", cookie: cookie)
        XCTAssertEqual(mismatch, .badRequest)
        let deleted = try await adminPost("/admin/businesses/\(id)/delete",
                                          form: "csrf=\(csrf)&confirmName=Acme%20AG", cookie: cookie)
        XCTAssertEqual(deleted, .seeOther)
        let remaining = try await BusinessDevice.query(on: app.db).count()
        XCTAssertEqual(remaining, 0)
        try await app.test(.GET, "v1/businesses/\(id)/logo") { res async in
            XCTAssertEqual(res.status, .notFound)
        }
    }
}
