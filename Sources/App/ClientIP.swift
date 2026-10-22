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
///   - CIDR list        → comma-separated ranges and/or the keywords `loopback`, `private`,
///                        `cloudflare` (opt-in, e.g. `TRUST_PROXY=private,cloudflare` when the
///                        API sits behind Cloudflare, so its edge isn't taken for the client)
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

    /// https://www.cloudflare.com/ips/ (checked 2026-10-22)
    static let cloudflareRanges = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ]

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
            case "cloudflare": return cloudflareRanges.compactMap(CIDR.init)
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
