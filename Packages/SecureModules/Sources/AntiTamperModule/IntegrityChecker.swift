import CryptoKit
import Foundation
import SecurityCore

/// Basic app-integrity checks that catch naive re-signing / repackaging.
///
/// A repackaged app (e.g. a cracked IPA re-signed with a different certificate, possibly with an
/// injected dylib) usually has a different bundle ID, a different team, or a modified executable.
public struct IntegrityChecker: Sendable {
    public let expectedBundleIdentifier: String
    /// Optional known-good SHA-256 of the main executable (hex), e.g. delivered by your backend
    /// per release. When `nil`, the hash is only reported.
    public let expectedExecutableHash: String?
    private let bundle: @Sendable () -> Bundle

    public init(
        expectedBundleIdentifier: String,
        expectedExecutableHash: String? = nil,
        bundle: @escaping @Sendable () -> Bundle = { .main }
    ) {
        self.expectedBundleIdentifier = expectedBundleIdentifier
        self.expectedExecutableHash = expectedExecutableHash
        self.bundle = bundle
    }

    public func run() -> [SecurityCheck] {
        [bundleIdentifierCheck(), provisioningProfileCheck(), codeSignatureCheck(), executableHashCheck()]
    }

    func bundleIdentifierCheck() -> SecurityCheck {
        let actual = bundle().bundleIdentifier ?? "<none>"
        let matches = actual == expectedBundleIdentifier
        return SecurityCheck(
            id: "bundle-id",
            name: "Bundle identifier",
            detail: matches ? "\(actual) matches." : "Expected \(expectedBundleIdentifier), found \(actual).",
            status: matches ? .passed : .failed
        )
    }

    /// App Store builds have no `embedded.mobileprovision`; development, ad-hoc and re-signed builds do.
    func provisioningProfileCheck() -> SecurityCheck {
        let hasProfile = bundle().path(forResource: "embedded", ofType: "mobileprovision") != nil
        let detail: String
        let status: CheckStatus
        if RuntimeEnvironment.isSimulator {
            detail = "Simulator builds are not provisioned."
            status = .info
        } else if hasProfile {
            detail = "embedded.mobileprovision present — normal for dev/TestFlight, suspicious for an App Store build."
            status = RuntimeEnvironment.isDebugBuild ? .info : .warning
        } else {
            detail = "No embedded profile (App Store distribution)."
            status = .passed
        }
        return SecurityCheck(id: "profile", name: "Provisioning profile", detail: detail, status: status)
    }

    func codeSignatureCheck() -> SecurityCheck {
        let url = bundle().bundleURL.appending(path: "_CodeSignature/CodeResources")
        let exists = FileManager.default.fileExists(atPath: url.path(percentEncoded: false))
        return SecurityCheck(
            id: "codesign",
            name: "Code signature",
            detail: exists ? "_CodeSignature/CodeResources present." : "Code signature resources missing.",
            status: exists ? .passed : (RuntimeEnvironment.isSimulator ? .warning : .failed)
        )
    }

    func executableHashCheck() -> SecurityCheck {
        guard
            let url = bundle().executableURL,
            let data = try? Data(contentsOf: url, options: .mappedIfSafe)
        else {
            return SecurityCheck(id: "exe-hash", name: "Executable hash", detail: "Could not read the executable.", status: .warning)
        }
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard let expectedExecutableHash else {
            return SecurityCheck(
                id: "exe-hash",
                name: "Executable hash",
                detail: "SHA-256 \(hash.prefix(16))… — compare server-side against the hash of your release build.",
                status: .info
            )
        }
        let matches = hash == expectedExecutableHash.lowercased()
        return SecurityCheck(
            id: "exe-hash",
            name: "Executable hash",
            detail: matches ? "Matches the known-good build." : "Executable was modified (\(hash.prefix(16))…).",
            status: matches ? .passed : .failed
        )
    }
}
