import Vapor
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Resolves the real client address behind reverse proxies without trusting
/// anything a client can forge.
///
/// `TRUST_PROXY` (same idea as Express' "trust proxy"):
///   - unset            → trust loopback + private networks (Docker/Traefik on Coolify)
///   - `none`/`false`   → ignore `X-Forwarded-For`, use the TCP peer
///   - a number N       → exactly N proxies sit in front; take the address they saw
///   - CIDR list        → comma-separated ranges and/or the keywords `loopback`, `private`
///
/// The `X-Forwarded-For` chain plus the TCP peer is walked from the right; the
/// first address that is not a trusted proxy is the client. Entries further left
/// were written by the client itself and are never used.
struct ClientIPResolver: Sendable {
    enum Mode: Sendable {
        case none
        case hops(Int)
        case ranges([CIDR])
    }

    let mode: Mode

    static let defaultRanges = ["loopback", "private"]

    static func fromEnvironment(_ raw: String?) -> ClientIPResolver {
        guard let raw = raw?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
            return ClientIPResolver(mode: .ranges(expand(defaultRanges)))
        }
        switch raw.lowercased() {
        case "none", "false", "0":
            return ClientIPResolver(mode: .none)
        default:
            if let hops = Int(raw), hops > 0 { return ClientIPResolver(mode: .hops(hops)) }
            let parts = raw.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            return ClientIPResolver(mode: .ranges(expand(parts)))
        }
    }

    private static func expand(_ entries: [String]) -> [CIDR] {
        entries.flatMap { entry -> [CIDR] in
            switch entry.lowercased() {
            case "loopback": return ["127.0.0.0/8", "::1/128"].compactMap(CIDR.init)
            case "private":
                return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                        "fc00::/7", "fe80::/10"].compactMap(CIDR.init)
            default: return CIDR(entry).map { [$0] } ?? []
            }
        }
    }

    func clientIP(for req: Request) -> String {
        clientIP(peer: req.remoteAddress?.ipAddress, forwardedFor: req.headers[.xForwardedFor])
    }

    func clientIP(peer rawPeer: String?, forwardedFor: [String]) -> String {
        let peer = rawPeer.map(IPAddress.normalize) ?? "unknown"
        if case .none = mode { return peer }
        let forwarded = forwardedFor
            .flatMap { $0.split(separator: ",") }
            .map { IPAddress.normalize($0.trimmingCharacters(in: .whitespaces)) }
        let chain = forwarded + [peer]

        switch mode {
        case .none:
            return peer
        case .hops(let hops):
            let index = chain.count - 1 - hops
            guard index >= 0, IPAddress.parse(chain[index]) != nil else {
                // Fewer hops than configured: something bypassed a proxy. The
                // left-most address we can see is the safest answer.
                return chain.first(where: { IPAddress.parse($0) != nil }) ?? peer
            }
            return chain[index]
        case .ranges(let trusted):
            var candidate = peer
            for address in chain.reversed() {
                guard let bytes = IPAddress.parse(address) else { return candidate }
                candidate = address
                if !trusted.contains(where: { $0.contains(bytes) }) { return address }
            }
            return candidate
        }
    }
}

struct CIDR: Sendable {
    let network: [UInt8]
    let prefix: Int

    init?(_ string: String) {
        let parts = string.split(separator: "/", maxSplits: 1)
        guard let address = parts.first, let bytes = IPAddress.parse(String(address)) else {
            return nil
        }
        let prefix = parts.count == 2 ? Int(parts[1]) : bytes.count * 8
        guard let prefix, (0...(bytes.count * 8)).contains(prefix) else { return nil }
        network = bytes
        self.prefix = prefix
    }

    func contains(_ address: [UInt8]) -> Bool {
        guard address.count == network.count else { return false }
        var remaining = prefix
        for index in network.indices where remaining > 0 {
            let bits = min(8, remaining)
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
            if address[index] & mask != network[index] & mask { return false }
            remaining -= bits
        }
        return true
    }
}

enum IPAddress {
    /// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is reported as plain IPv4 so both
    /// spellings share one rate-limit bucket.
    static func normalize(_ raw: String) -> String {
        let lowered = raw.lowercased()
        if lowered.hasPrefix("::ffff:"), parseV4(String(raw.dropFirst(7))) != nil {
            return String(raw.dropFirst(7))
        }
        return raw
    }

    static func parse(_ string: String) -> [UInt8]? {
        parseV4(string) ?? parseV6(string)
    }

    private static func parseV4(_ string: String) -> [UInt8]? {
        var address = in_addr()
        guard inet_pton(AF_INET, string, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    private static func parseV6(_ string: String) -> [UInt8]? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, string, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }
}

extension Application {
    private struct ClientIPResolverKey: StorageKey { typealias Value = ClientIPResolver }

    var clientIPResolver: ClientIPResolver {
        get { storage[ClientIPResolverKey.self] ?? .fromEnvironment(nil) }
        set { storage[ClientIPResolverKey.self] = newValue }
    }
}

extension Request {
    var clientIP: String { application.clientIPResolver.clientIP(for: self) }
}
