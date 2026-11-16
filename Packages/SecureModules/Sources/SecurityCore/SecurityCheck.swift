import Foundation

/// Outcome of a single security check.
public enum CheckStatus: String, Sendable, Hashable {
    /// Nothing suspicious found.
    case passed
    /// Something suspicious was found.
    case failed
    /// Inconclusive, or only meaningful in some environments (e.g. simulator).
    case warning
    /// Purely informational.
    case info
}

/// A single, named check with a human-readable explanation of what was found.
public struct SecurityCheck: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let detail: String
    public let status: CheckStatus

    public init(id: String, name: String, detail: String, status: CheckStatus) {
        self.id = id
        self.name = name
        self.detail = detail
        self.status = status
    }
}

/// Overall risk derived from a set of checks.
public enum RiskLevel: String, Sendable, Comparable {
    case low = "Low"
    case medium = "Medium"
    case high = "High"

    private var rank: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.rank < rhs.rank }

    /// One failed check → medium, two or more → high. Warnings never raise the level on their own.
    public init(checks: [SecurityCheck]) {
        let failures = checks.filter { $0.status == .failed }.count
        switch failures {
        case 0: self = .low
        case 1: self = .medium
        default: self = .high
        }
    }
}

/// Where the app is running. Many runtime-integrity checks are meaningless on the simulator,
/// because the simulator process sees the host Mac's file system and is always debuggable.
public enum RuntimeEnvironment {
    public static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        true
        #else
        false
        #endif
    }

    public static var isDebugBuild: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }
}
