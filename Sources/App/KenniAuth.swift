import Vapor
import Crypto

/// Proof-of-key authentication. Every authenticated request carries:
///
///   X-Kenni-Id:        base64url Ed25519 public key (32 bytes)
///   X-Kenni-Timestamp: unix seconds, must be within ±300 s
///   X-Kenni-Signature: base64url Ed25519 signature over
///                      "kenni/v1/api\n{METHOD}\n{path}\n{timestamp}\n{body}"
///
/// The server learns *that* the caller owns the key — never anything about
/// who the person is.
struct KenniAuth {
    let keyID: String
    let publicKey: Curve25519.Signing.PublicKey

    static func verify(_ req: Request, body: ByteBuffer?) throws -> KenniAuth {
        guard
            let keyID = req.headers.first(name: "X-Kenni-Id"),
            let timestampRaw = req.headers.first(name: "X-Kenni-Timestamp"),
            let signatureRaw = req.headers.first(name: "X-Kenni-Signature"),
            let keyData = Data(base64URLEncoded: keyID), keyData.count == 32,
            let signature = Data(base64URLEncoded: signatureRaw),
            let timestamp = Double(timestampRaw)
        else {
            throw Abort(.unauthorized, reason: "missing or malformed auth headers")
        }

        guard abs(Date().timeIntervalSince1970 - timestamp) <= 300 else {
            throw Abort(.unauthorized, reason: "timestamp outside allowed window")
        }

        let bodyString: String
        if let body {
            bodyString = String(buffer: body)
        } else {
            bodyString = ""
        }
        let message = Data("kenni/v1/api\n\(req.method.rawValue)\n\(req.url.path)\n\(timestampRaw)\n\(bodyString)".utf8)

        guard
            let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData),
            publicKey.isValidSignature(signature, for: message)
        else {
            throw Abort(.unauthorized, reason: "invalid signature")
        }

        return KenniAuth(keyID: keyID, publicKey: publicKey)
    }
}

extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
