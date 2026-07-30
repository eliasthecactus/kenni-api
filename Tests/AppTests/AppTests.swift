import XCTVapor
import Crypto
@testable import App

final class AppTests: XCTestCase {
    var app: Application!

    override func setUp() async throws {
        app = try await Application.make(.testing)
        try await configure(app, businessConfiguration: BusinessConfiguration(
            adminPSK: "test-admin-key", businessSecret: "test-business-token-secret"))
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        app = nil
    }

    /// Signs a request the way the iOS client does.
    private func signedHeaders(method: String, path: String, body: String,
                               key: Curve25519.Signing.PrivateKey) throws -> HTTPHeaders {
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let message = Data("kenni/v1/api\n\(method)\n\(path)\n\(timestamp)\n\(body)".utf8)
        let signature = try key.signature(for: message)
        var headers = HTTPHeaders()
        headers.add(name: "X-Kenni-Id", value: key.publicKey.rawRepresentation.base64URLEncodedString())
        headers.add(name: "X-Kenni-Timestamp", value: timestamp)
        headers.add(name: "X-Kenni-Signature", value: signature.base64URLEncodedString())
        headers.contentType = .json
        return headers
    }

    private func businessHeaders(method: String, path: String, body: String,
                                 deviceID: UUID,
                                 key: Curve25519.Signing.PrivateKey) throws -> HTTPHeaders {
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let message = Data(
            "kenni/v1/business-device\n\(method)\n\(path)\n\(timestamp)\n\(body)".utf8)
        let signature = try key.signature(for: message)
        var headers = HTTPHeaders()
        headers.add(name: "X-Kenni-Business-Device", value: deviceID.uuidString)
        headers.add(name: "X-Kenni-Business-Timestamp", value: timestamp)
        headers.add(name: "X-Kenni-Business-Signature",
                    value: signature.base64URLEncodedString())
        headers.contentType = .json
        return headers
    }

    func testHealth() async throws {
        try await app.test(.GET, "health") { res async in
            XCTAssertEqual(res.status, .ok)
        }
    }

    func testDeviceRegistrationRequiresValidSignature() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let body = #"{"apnsToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#

        // No auth headers → unauthorized.
        try await app.test(.POST, "v1/devices", beforeRequest: { req in
            req.headers.contentType = .json
            req.body = ByteBuffer(string: body)
        }) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }

        // Properly signed → ok.
        let headers = try signedHeaders(method: "POST", path: "/v1/devices", body: body, key: key)
        try await app.test(.POST, "v1/devices", beforeRequest: { req in
            req.headers = headers
            req.body = ByteBuffer(string: body)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
        }

        // Tampered body (signature no longer matches) → unauthorized.
        try await app.test(.POST, "v1/devices", beforeRequest: { req in
            req.headers = headers
            req.body = ByteBuffer(string: #"{"apnsToken":"EVIL"}"#)
        }) { res async in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }


    func testDeviceTokenValidation() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let body = #"{"apnsToken":"not-hex!!"}"#
        try await app.test(.POST, "v1/devices", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST", path: "/v1/devices",
                                                 body: body, key: key)
            req.body = ByteBuffer(string: body)
        }) { res async in
            XCTAssertEqual(res.status, .badRequest)
        }
    }

    func testVerificationRelayFlow() async throws {
        let alice = Curve25519.Signing.PrivateKey()
        let bob = Curve25519.Signing.PrivateKey()
        let bobID = bob.publicKey.rawRepresentation.base64URLEncodedString()

        // Bob registers his device.
        let regBody = #"{"apnsToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
        try await app.test(.POST, "v1/devices", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST", path: "/v1/devices",
                                                 body: regBody, key: bob)
            req.body = ByteBuffer(string: regBody)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
        }

        // Alice files a verification request addressed to Bob.
        let reqID = UUID().uuidString
        let reqBody = #"{"requestID":"\#(reqID)","to":"\#(bobID)","payload":"signed-envelope"}"#
        try await app.test(.POST, "v1/verify/requests", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST", path: "/v1/verify/requests",
                                                 body: reqBody, key: alice)
            req.body = ByteBuffer(string: reqBody)
        }) { res async in
            XCTAssertEqual(res.status, .created)
        }

        // Replayed request id is rejected.
        try await app.test(.POST, "v1/verify/requests", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST", path: "/v1/verify/requests",
                                                 body: reqBody, key: alice)
            req.body = ByteBuffer(string: reqBody)
        }) { res async in
            XCTAssertEqual(res.status, .conflict)
        }

        // A third party cannot answer.
        let eve = Curve25519.Signing.PrivateKey()
        let respBody = #"{"payload":"eve-envelope"}"#
        try await app.test(.POST, "v1/verify/requests/\(reqID)/response", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST",
                                                 path: "/v1/verify/requests/\(reqID)/response",
                                                 body: respBody, key: eve)
            req.body = ByteBuffer(string: respBody)
        }) { res async in
            XCTAssertEqual(res.status, .forbidden)
        }

        // Bob answers.
        let bobRespBody = #"{"payload":"bob-signed-answer"}"#
        try await app.test(.POST, "v1/verify/requests/\(reqID)/response", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "POST",
                                                 path: "/v1/verify/requests/\(reqID)/response",
                                                 body: bobRespBody, key: bob)
            req.body = ByteBuffer(string: bobRespBody)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
        }

        // Alice polls and sees the answer.
        try await app.test(.GET, "v1/verify/requests/\(reqID)", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "GET",
                                                 path: "/v1/verify/requests/\(reqID)",
                                                 body: "", key: alice)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
            let status = try? res.content.decode(VerifyStatusDTO.self)
            XCTAssertEqual(status?.status, "answered")
            XCTAssertEqual(status?.responsePayload, "bob-signed-answer")
        }
    }

    func testBackupRoundtrip() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let body = #"{"blob":"encrypted-contacts"}"#
        try await app.test(.PUT, "v1/backup", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "PUT", path: "/v1/backup",
                                                 body: body, key: key)
            req.body = ByteBuffer(string: body)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
        }
        try await app.test(.GET, "v1/backup", beforeRequest: { req in
            req.headers = try self.signedHeaders(method: "GET", path: "/v1/backup",
                                                 body: "", key: key)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
            let backup = try? res.content.decode(BackupDTO.self)
            XCTAssertEqual(backup?.blob, "encrypted-contacts")
        }
    }

    func testAdminEnrollmentPINAndRevocationLifecycle() async throws {
        try await app.test(.GET, "admin") { res async in
            XCTAssertEqual(res.status, .unauthorized)
            XCTAssertEqual(res.headers.contentType?.type, "text")
        }

        var cookie: String?
        try await app.test(.POST, "admin/login", beforeRequest: { req in
            req.headers.replaceOrAdd(
                name: "Content-Type", value: "application/x-www-form-urlencoded")
            req.body = ByteBuffer(string: "psk=test-admin-key")
        }) { res async in
            XCTAssertEqual(res.status, .seeOther)
            cookie = res.headers.first(name: "Set-Cookie")?
                .split(separator: ";").first.map(String.init)
        }
        let sessionCookie = try XCTUnwrap(cookie)

        var csrf: String?
        try await app.test(.GET, "admin", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie)
        }) { res async in
            XCTAssertEqual(res.status, .ok)
            let marker = #"name="csrf" value=""#
            if let markerRange = res.body.string.range(of: marker) {
                csrf = String(res.body.string[markerRange.upperBound...].prefix { $0 != "\"" })
            }
        }
        let csrfToken = try XCTUnwrap(csrf)

        try await app.test(.POST, "admin/businesses", beforeRequest: { req in
            req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie)
            req.headers.replaceOrAdd(
                name: "Content-Type", value: "application/x-www-form-urlencoded")
            req.body = ByteBuffer(string:
                "csrf=\(csrfToken)&name=Acme%20AG&logoURL=https%3A%2F%2Fexample.com%2Flogo.png&address=Main%20Street%201%0A8000%20Zurich&websiteURL=https%3A%2F%2Fexample.com")
        }) { res async in
            XCTAssertEqual(res.status, .seeOther)
        }
        let createdBusiness = try await Business.query(on: app.db).first()
        let business = try XCTUnwrap(createdBusiness)
        let businessID = try business.requireID()

        var enrollmentToken: String?
        try await app.test(
            .POST, "admin/businesses/\(businessID)/devices",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie)
                req.headers.replaceOrAdd(
                    name: "Content-Type", value: "application/x-www-form-urlencoded")
                req.body = ByteBuffer(
                    string: "csrf=\(csrfToken)&deviceLabel=Reception%20iPad")
            }
        ) { res async in
            XCTAssertEqual(res.status, .created)
            XCTAssertTrue(res.body.string.contains("<svg"))
            let marker = "kenni://business/enroll?token="
            if let markerRange = res.body.string.range(of: marker) {
                enrollmentToken = String(
                    res.body.string[markerRange.upperBound...].prefix { $0 != "<" })
            }
        }
        let token = try XCTUnwrap(enrollmentToken)

        let deviceKey = Curve25519.Signing.PrivateKey()
        let publicKey = deviceKey.publicKey.rawRepresentation.base64URLEncodedString()
        let enrollmentSignature = try deviceKey.signature(
            for: BusinessDeviceAuth.enrollmentMessage(token: token, publicKey: publicKey))
            .base64URLEncodedString()
        let claimData = try JSONEncoder().encode(ClaimBusinessDeviceDTO(
            token: token, publicKey: publicKey, signature: enrollmentSignature))
        let claimBody = String(decoding: claimData, as: UTF8.self)
        let forgedSignature = try Curve25519.Signing.PrivateKey().signature(
            for: BusinessDeviceAuth.enrollmentMessage(token: token, publicKey: publicKey))
            .base64URLEncodedString()
        let forgedClaimData = try JSONEncoder().encode(ClaimBusinessDeviceDTO(
            token: token, publicKey: publicKey, signature: forgedSignature))
        try await app.test(
            .POST, "v1/business-device-invitations/claim",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: forgedClaimData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }
        var credential: BusinessDeviceCredentialDTO?
        try await app.test(
            .POST, "v1/business-device-invitations/claim",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(string: claimBody)
            }
        ) { res async in
            XCTAssertEqual(res.status, .ok)
            credential = try? res.content.decode(BusinessDeviceCredentialDTO.self)
            XCTAssertEqual(credential?.deviceLabel, "Reception iPad")
            XCTAssertEqual(credential?.business.name, "Acme AG")
            XCTAssertEqual(credential?.business.address, "Main Street 1\n8000 Zurich")
        }
        let enrolled = try XCTUnwrap(credential)

        try await app.test(
            .POST, "v1/business-device-invitations/claim",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(string: claimBody)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }

        let pinPath = "/v1/business-devices/verification-pins"
        func issuePIN() async throws -> BusinessPINDTO {
            var issuedPIN: BusinessPINDTO?
            try await app.test(
                .POST, String(pinPath.dropFirst()),
                beforeRequest: { req in
                    req.headers = try self.businessHeaders(
                        method: "POST", path: pinPath, body: "",
                        deviceID: enrolled.deviceID, key: deviceKey)
                }
            ) { res async in
                XCTAssertEqual(res.status, .ok)
                issuedPIN = try? res.content.decode(BusinessPINDTO.self)
            }
            return try XCTUnwrap(issuedPIN)
        }

        let issued = try await issuePIN()
        XCTAssertEqual(issued.pin.count, 6)
        XCTAssertTrue(issued.pin.allSatisfy(\.isNumber))
        XCTAssertGreaterThan(issued.expiresAt, Int(Date().timeIntervalSince1970))

        let wrongPIN = issued.pin == "000000" ? "000001" : "000000"
        let wrongData = try JSONEncoder().encode(VerifyBusinessPINDTO(pin: wrongPIN))
        try await app.test(
            .POST, "v1/business-verifications/verify",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: wrongData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }

        let verificationData = try JSONEncoder().encode(
            VerifyBusinessPINDTO(pin: issued.pin))
        try await app.test(
            .POST, "v1/business-verifications/verify",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: verificationData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .ok)
            let verified = try? res.content.decode(BusinessDTO.self)
            XCTAssertEqual(verified?.id, businessID)
            XCTAssertEqual(verified?.name, "Acme AG")
        }
        try await app.test(
            .POST, "v1/business-verifications/verify",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: verificationData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }

        let replacedPIN = try await issuePIN()
        let pendingRevocation = try await issuePIN()
        let replacedData = try JSONEncoder().encode(
            VerifyBusinessPINDTO(pin: replacedPIN.pin))
        try await app.test(
            .POST, "v1/business-verifications/verify",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: replacedData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }

        try await app.test(
            .POST, "admin/businesses/\(businessID)/devices/\(enrolled.deviceID)/revoke",
            beforeRequest: { req in
                req.headers.replaceOrAdd(name: "Cookie", value: sessionCookie)
                req.headers.replaceOrAdd(
                    name: "Content-Type", value: "application/x-www-form-urlencoded")
                req.body = ByteBuffer(string: "csrf=\(csrfToken)")
            }
        ) { res async in
            XCTAssertEqual(res.status, .seeOther)
        }

        let revokedData = try JSONEncoder().encode(
            VerifyBusinessPINDTO(pin: pendingRevocation.pin))
        try await app.test(
            .POST, "v1/business-verifications/verify",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(data: revokedData)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }
        try await app.test(
            .POST, String(pinPath.dropFirst()),
            beforeRequest: { req in
                req.headers = try self.businessHeaders(
                    method: "POST", path: pinPath, body: "",
                    deviceID: enrolled.deviceID, key: deviceKey)
            }
        ) { res async in
            XCTAssertEqual(res.status, .gone)
        }

        let statusPath = "/v1/business-devices/me"
        try await app.test(
            .GET, String(statusPath.dropFirst()),
            beforeRequest: { req in
                req.headers = try self.businessHeaders(
                    method: "GET", path: statusPath, body: "",
                    deviceID: enrolled.deviceID, key: deviceKey)
            }
        ) { res async in
            XCTAssertEqual(res.status, .ok)
            let status = try? res.content.decode(BusinessDeviceStatusDTO.self)
            XCTAssertEqual(status?.status, "revoked")
            XCTAssertNotNil(status?.revokedAt)
        }
    }

    func testAdminAndBusinessEnrollmentLockWhenEnvironmentIsMissing() async throws {
        let lockedApp = try await Application.make(.testing)
        try await configure(lockedApp, businessConfiguration: BusinessConfiguration(
            adminPSK: nil, businessSecret: nil))

        try await lockedApp.test(.GET, "admin") { res async in
            XCTAssertEqual(res.status, .serviceUnavailable)
            XCTAssertTrue(res.body.string.contains("Admin access is locked"))
        }
        try await lockedApp.test(
            .POST, "v1/business-device-invitations/claim",
            beforeRequest: { req in
                req.headers.contentType = .json
                req.body = ByteBuffer(
                    string: #"{"token":"unused","publicKey":"unused","signature":"unused"}"#)
            }
        ) { res async in
            XCTAssertEqual(res.status, .serviceUnavailable)
        }
        try await lockedApp.asyncShutdown()
    }
}
