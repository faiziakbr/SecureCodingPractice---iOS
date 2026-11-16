import Foundation
import LocalAuthentication

/// The kind of biometry the device offers.
public enum BiometryKind: Sendable {
    case none, touchID, faceID, opticID

    init(_ type: LABiometryType) {
        switch type {
        case .touchID: self = .touchID
        case .faceID: self = .faceID
        case .opticID: self = .opticID
        case .none: self = .none
        @unknown default: self = .none
        }
    }

    public var displayName: String {
        switch self {
        case .none: "No biometrics"
        case .touchID: "Touch ID"
        case .faceID: "Face ID"
        case .opticID: "Optic ID"
        }
    }

    public var systemImage: String {
        switch self {
        case .none: "lock.fill"
        case .touchID: "touchid"
        case .faceID: "faceid"
        case .opticID: "opticid"
        }
    }
}

public struct BiometricAvailability: Sendable {
    public let kind: BiometryKind
    public let isAvailable: Bool
    /// Why biometrics can't be used right now (not enrolled, locked out, no passcode, ...).
    public let unavailableReason: String?
}

/// User-facing mapping of `LAError` codes.
public enum BiometricError: Error, LocalizedError, Equatable {
    case userCanceled
    case userFallback
    case notAvailable
    case notEnrolled
    case lockedOut
    case passcodeNotSet
    case failed
    case other(String)

    init(_ error: Error) {
        guard let laError = error as? LAError else {
            self = .other(error.localizedDescription)
            return
        }
        switch laError.code {
        case .userCancel, .systemCancel, .appCancel: self = .userCanceled
        case .userFallback: self = .userFallback
        case .biometryNotAvailable: self = .notAvailable
        case .biometryNotEnrolled: self = .notEnrolled
        case .biometryLockout: self = .lockedOut
        case .passcodeNotSet: self = .passcodeNotSet
        case .authenticationFailed: self = .failed
        default: self = .other(laError.localizedDescription)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .userCanceled: "Authentication was canceled."
        case .userFallback: "User chose to enter the password instead."
        case .notAvailable: "Biometrics are not available on this device."
        case .notEnrolled: "No Face ID / Touch ID enrolled. (Simulator: Features ▸ Face ID ▸ Enrolled)"
        case .lockedOut: "Biometrics locked after too many failed attempts. Unlock with passcode first."
        case .passcodeNotSet: "A device passcode is required for biometrics."
        case .failed: "Biometric authentication failed."
        case .other(let message): message
        }
    }
}

/// Wraps `LAContext` for simple "is the device owner present?" checks.
///
/// - Important: A boolean result from `evaluatePolicy` only gates UI. On a compromised device it can
///   be hooked to always return `true`. To actually protect a secret, bind it to biometrics in the
///   Keychain with `BiometricVault`, so the Secure Enclave releases it only after a real match.
public struct BiometricAuthenticator: Sendable {
    public enum Policy: Sendable {
        /// Biometrics only (Face ID / Touch ID / Optic ID).
        case biometricsOnly
        /// Biometrics with automatic fallback to the device passcode.
        case biometricsOrPasscode

        var laPolicy: LAPolicy {
            switch self {
            case .biometricsOnly: .deviceOwnerAuthenticationWithBiometrics
            case .biometricsOrPasscode: .deviceOwnerAuthentication
            }
        }
    }

    public init() {}

    public func availability(for policy: Policy = .biometricsOnly) -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(policy.laPolicy, error: &error)
        return BiometricAvailability(
            kind: BiometryKind(context.biometryType),
            isAvailable: canEvaluate,
            unavailableReason: error.map { BiometricError($0).localizedDescription }
        )
    }

    /// Prompts the user. Returns normally on success, throws `BiometricError` otherwise.
    public func authenticate(reason: String, policy: Policy = .biometricsOnly) async throws(BiometricError) {
        let context = LAContext()
        context.localizedFallbackTitle = policy == .biometricsOnly ? "" : nil // hide "Enter Password" when biometrics only
        do {
            _ = try await context.evaluatePolicy(policy.laPolicy, localizedReason: reason)
        } catch {
            throw BiometricError(error)
        }
    }

    /// Opaque hash of the currently enrolled biometric set. If it changes between launches,
    /// someone added or removed a face/finger — treat that as a reason to re-authenticate with
    /// a password before trusting biometrics again.
    public func currentEnrollmentState() -> Data? {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return nil
        }
        if #available(iOS 18.0, *) {
            return context.domainState.biometry.stateHash
        }
        return legacyEnrollmentState(context)
    }

    @available(iOS, deprecated: 18.0, message: "Use domainState.biometry.stateHash on iOS 18+")
    private func legacyEnrollmentState(_ context: LAContext) -> Data? {
        context.evaluatedPolicyDomainState
    }
}
