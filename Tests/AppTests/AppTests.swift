import XCTVapor
import Crypto
@testable import App

final class AppTests: XCTestCase {
    var app: Application!

    override func setUp() async throws {
        app = try await Application.make(.testing)
        try await configure(app)
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
}
