import Foundation

/// Pins for one host (optionally including its subdomains).
public struct PinnedHost: Sendable, Hashable {
    public let host: String
    /// Base64 SHA-256 SPKI hashes. A connection succeeds if **any** certificate in the validated
    /// chain (leaf, intermediate or root CA) matches **any** pin. Always ship at least one backup pin.
    public let pins: Set<String>
    public let includesSubdomains: Bool

    public init(host: String, pins: Set<String>, includesSubdomains: Bool = false) {
        self.host = host.lowercased()
        self.pins = pins
        self.includesSubdomains = includesSubdomains
    }

    func matches(_ candidate: String) -> Bool {
        let candidate = candidate.lowercased()
        return candidate == host || (includesSubdomains && candidate.hasSuffix("." + host))
    }
}

/// What to do when a pinned host is contacted.
public struct PinningPolicy: Sendable {
    public let pinnedHosts: [PinnedHost]
    /// When `true`, connections to hosts that have no pins are rejected (strict allow-list).
    public let rejectUnpinnedHosts: Bool

    public init(pinnedHosts: [PinnedHost], rejectUnpinnedHosts: Bool = false) {
        self.pinnedHosts = pinnedHosts
        self.rejectUnpinnedHosts = rejectUnpinnedHosts
    }

    /// Pins applicable to `host`, or `nil` if the host isn't pinned.
    public func pins(for host: String) -> Set<String>? {
        let matching = pinnedHosts.filter { $0.matches(host) }
        guard !matching.isEmpty else { return nil }
        return matching.reduce(into: Set<String>()) { $0.formUnion($1.pins) }
    }
}

/// Well-known pins used by the demo.
///
/// Computed with `openssl s_client -connect www.google.com:443 -showcerts` followed by the SPKI
/// hash pipeline documented on `SPKIHasher`. Pinning Google Trust Services **root CA keys** is
/// "CA pinning": the leaf and intermediate certificates can rotate freely, but only certificates
/// issued under these CAs are accepted.
public enum DemoPins {
    public static let gtsRootR1 = "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc="
    public static let gtsRootR2 = "Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78="
    public static let gtsRootR3 = "QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g="
    public static let gtsRootR4 = "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="
    /// GlobalSign Root CA — cross-signs GTS roots for legacy clients.
    public static let globalSignRootCA = "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="

    /// A syntactically valid pin that matches nothing — simulates a MITM proxy / wrong server.
    public static let bogus = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    public static let googleCAPins: Set<String> = [gtsRootR1, gtsRootR2, gtsRootR3, gtsRootR4, globalSignRootCA]
}
