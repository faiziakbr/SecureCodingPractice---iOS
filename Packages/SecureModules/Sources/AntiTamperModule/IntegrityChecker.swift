import CryptoKit
import Foundation
import SecurityCore

/// Basic app-integrity checks that catch naive re-signing / repackaging.
///
/// A repackaged app (e.g. a cracked IPA re-signed with a different certificate, possibly with an
/// injected dylib) usually has a different bundle ID, a different team, or a modified executable.
public struct IntegrityChecker: Sendable {
    public let expectedBundleIdentifier: String
    /// Optional known-good SHA-256 of the main executable (hex). When `nil`, the hash is only reported.
    ///
    /// - Important: Only usable when you hash the *exact* binary you distribute (ad-hoc or
    ///   enterprise IPAs, after export/signing — the code signature lives inside the Mach-O).
    ///   App Store binaries are FairPlay-encrypted and re-signed by Apple, so the installed
    ///   executable never matches the build you uploaded; the comparison is skipped there.
    ///   Debug builds are also skipped: the executable is a stub and the code lives in
    ///   `*.debug.dylib`. For real integrity guarantees use App Attest (`DCAppAttestService`).
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
    private var hasEmbeddedProfile: Bool {
        bundle().path(forResource: "embedded", ofType: "mobileprovision") != nil
    }

    /// No embedded profile on a device build → App Store distribution (a re-signer can also strip it,
    /// which is why this only decides whether a hash comparison is possible, not whether to trust).
    private var looksLikeAppStoreInstall: Bool {
        !RuntimeEnvironment.isSimulator && !hasEmbeddedProfile
    }

    func provisioningProfileCheck() -> SecurityCheck {
        let hasProfile = hasEmbeddedProfile
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
        let summary = "SHA-256 \(hash.prefix(16))…"

        if RuntimeEnvironment.isDebugBuild {
            return SecurityCheck(
                id: "exe-hash",
                name: "Executable hash",
                detail: "\(summary) — Debug build: the executable is a stub (code is in *.debug.dylib), so this hash says nothing about integrity.",
                status: .info
            )
        }
        if looksLikeAppStoreInstall {
            return SecurityCheck(
                id: "exe-hash",
                name: "Executable hash",
                detail: "\(summary) — App Store binaries are encrypted and re-signed by Apple, so no build-time hash can match. Use App Attest instead.",
                status: .info
            )
        }
        guard let expectedExecutableHash else {
            return SecurityCheck(
                id: "exe-hash",
                name: "Executable hash",
                detail: "\(summary) — informational. Only comparable against the hash of the exact signed IPA you distributed (ad-hoc/enterprise).",
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
