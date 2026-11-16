import Foundation
import SecurityCore

/// Abstraction over file-system access so the detector can be unit-tested.
public protocol FileSystemProbing: Sendable {
    func fileExists(atPath path: String) -> Bool
    func isSymbolicLink(atPath path: String) -> Bool
    /// Attempts to write (and then remove) a file at `path`. Returns `true` if the write succeeded.
    func canWrite(toPath path: String) -> Bool
}

public struct LiveFileSystemProbe: FileSystemProbing {
    public init() {}

    public func fileExists(atPath path: String) -> Bool {
        // Use the C API too: FileManager can be hooked by a tweak that hides jailbreak files.
        FileManager.default.fileExists(atPath: path) || access(path, F_OK) == 0
    }

    public func isSymbolicLink(atPath path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }

    public func canWrite(toPath path: String) -> Bool {
        do {
            try "jailbreak-test".write(toFile: path, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false
        }
    }
}

/// Result of running every jailbreak heuristic.
public struct JailbreakReport: Sendable {
    public let checks: [SecurityCheck]
    public let isSimulator: Bool

    public var risk: RiskLevel { RiskLevel(checks: checks) }
    public var isLikelyJailbroken: Bool { checks.contains { $0.status == .failed } }
}

/// Layered jailbreak heuristics.
///
/// No single check is reliable — modern jailbreaks (rootless, Dopamine, palera1n) and hiding
/// tweaks (Shadow, Liberty Lite) defeat many of them. Combine several, run them at different
/// times, and treat the result as a *risk signal* to report to your backend, not a hard gate.
public struct JailbreakDetector: Sendable {
    /// Files and folders created by jailbreaks, package managers and tweak loaders.
    public static let suspiciousPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/TweakInject",
        "/usr/libexec/cydia",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/var/jb",                       // rootless jailbreaks (Dopamine, palera1n)
        "/var/binpack",
        "/private/preboot/jb",
        "/.bootstrapped",
        "/.installed_dopamine",
    ]

    /// System folders that jailbreaks historically replaced with symlinks.
    public static let symlinkPaths: [String] = [
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/arm-apple-darwin9",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
    ]

    /// Substrings of dylibs injected by tweak frameworks.
    public static let suspiciousLibraries: [String] = [
        "MobileSubstrate", "SubstrateLoader", "SubstrateInserter", "TweakInject", "libhooker",
        "libsubstitute", "libellekit", "SSLKillSwitch", "Shadow.dylib", "LibertyLite", "FridaGadget", "frida-agent",
        "cynject", "libcycript",
    ]

    private let fileSystem: any FileSystemProbing
    private let loadedImages: @Sendable () -> [String]
    private let environment: @Sendable (String) -> String?
    private let isSimulator: Bool

    public init(
        fileSystem: any FileSystemProbing = LiveFileSystemProbe(),
        loadedImages: @escaping @Sendable () -> [String] = LoadedImages.current,
        environment: @escaping @Sendable (String) -> String? = { ProcessInfo.processInfo.environment[$0] },
        isSimulator: Bool = RuntimeEnvironment.isSimulator
    ) {
        self.fileSystem = fileSystem
        self.loadedImages = loadedImages
        self.environment = environment
        self.isSimulator = isSimulator
    }

    public func run() -> JailbreakReport {
        var checks = [
            suspiciousFilesCheck(),
            sandboxCheck(),
            symlinkCheck(),
            injectedLibrariesCheck(),
            environmentCheck(),
        ]

        if isSimulator {
            // The simulator sees the host Mac's file system (/bin/bash, /usr/sbin/sshd exist on macOS),
            // so file-based checks produce false positives. Downgrade them to warnings.
            checks = checks.map { check in
                guard check.status == .failed else { return check }
                return SecurityCheck(id: check.id, name: check.name, detail: check.detail + " (expected on Simulator)", status: .warning)
            }
            checks.insert(
                SecurityCheck(id: "simulator", name: "Running on Simulator", detail: "Results are not meaningful — test on a real device.", status: .warning),
                at: 0
            )
        }

        return JailbreakReport(checks: checks, isSimulator: isSimulator)
    }

    // MARK: Individual checks

    func suspiciousFilesCheck() -> SecurityCheck {
        let found = Self.suspiciousPaths.filter(fileSystem.fileExists(atPath:))
        return SecurityCheck(
            id: "files",
            name: "Jailbreak files",
            detail: found.isEmpty ? "None of \(Self.suspiciousPaths.count) known paths exist." : "Found: \(found.joined(separator: ", "))",
            status: found.isEmpty ? .passed : .failed
        )
    }

    func sandboxCheck() -> SecurityCheck {
        let path = "/private/jailbreak-\(UUID().uuidString).txt"
        let escaped = fileSystem.canWrite(toPath: path)
        return SecurityCheck(
            id: "sandbox",
            name: "Sandbox integrity",
            detail: escaped ? "App could write outside its sandbox (\(path))." : "Writing outside the app container is blocked.",
            status: escaped ? .failed : .passed
        )
    }

    func symlinkCheck() -> SecurityCheck {
        let links = Self.symlinkPaths.filter(fileSystem.isSymbolicLink(atPath:))
        return SecurityCheck(
            id: "symlinks",
            name: "System folder symlinks",
            detail: links.isEmpty ? "System folders are real directories." : "Symlinked: \(links.joined(separator: ", "))",
            status: links.isEmpty ? .passed : .failed
        )
    }

    func injectedLibrariesCheck() -> SecurityCheck {
        let suspicious = LoadedImages.matching(Self.suspiciousLibraries, in: loadedImages())
        let names = suspicious.map { ($0 as NSString).lastPathComponent }
        return SecurityCheck(
            id: "dylibs",
            name: "Injected libraries",
            detail: names.isEmpty ? "No tweak/hooking libraries loaded." : "Loaded: \(names.joined(separator: ", "))",
            status: names.isEmpty ? .passed : .failed
        )
    }

    func environmentCheck() -> SecurityCheck {
        let value = environment("DYLD_INSERT_LIBRARIES")
        let flagged = !(value ?? "").isEmpty
        return SecurityCheck(
            id: "env",
            name: "DYLD_INSERT_LIBRARIES",
            detail: flagged ? "Set to: \(value ?? "")" : "Not set.",
            status: flagged ? .failed : .passed
        )
    }
}
