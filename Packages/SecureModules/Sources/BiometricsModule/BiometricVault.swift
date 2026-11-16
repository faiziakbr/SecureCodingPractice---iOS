import Foundation
import KeychainModule
import LocalAuthentication
import Security

/// Stores a secret in the Keychain behind a biometric access-control policy.
///
/// The OS — not your app code — enforces the check: `SecItemCopyMatching` only returns the data
/// after the Secure Enclave has verified a Face ID / Touch ID match. Hooking a boolean in your
/// app cannot bypass it. With `.biometryCurrentSet`, enrolling a new face/finger invalidates the item.
public struct BiometricVault: Sendable {
    public let service: String
    public let account: String

    public init(
        service: String = (Bundle.main.bundleIdentifier ?? "SecureCodingPractice") + ".biometric-vault",
        account: String = "vault-secret"
    ) {
        self.service = service
        self.account = account
    }

    /// Saves (or replaces) the secret. Requires a device passcode to be set.
    public func store(_ secret: Data) throws {
        var cfError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, // never leaves the device; wiped if passcode removed
            .biometryCurrentSet,                              // invalidated if biometric enrollment changes
            &cfError
        ) else {
            throw cfError?.takeRetainedValue() ?? KeychainError.unhandled(errSecParam)
        }

        // Access-control attributes can't be updated in place, so replace the item.
        SecItemDelete(baseQuery as CFDictionary)

        var query = baseQuery
        query[kSecValueData as String] = secret
        query[kSecAttrAccessControl as String] = accessControl

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    /// Reads the secret. Triggers the system biometric prompt.
    /// Runs off the main actor because `SecItemCopyMatching` blocks while the prompt is shown.
    @concurrent
    public func readSecret(reason: String) async throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "" // biometrics only

        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        guard let data = result as? Data else { throw KeychainError.invalidData }
        return data
    }

    /// Whether a secret exists, checked without triggering a biometric prompt.
    public var hasSecret: Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        var query = baseQuery
        query[kSecUseAuthenticationContext as String] = context
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // An item that needs auth reports errSecInteractionNotAllowed when interaction is disabled.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
