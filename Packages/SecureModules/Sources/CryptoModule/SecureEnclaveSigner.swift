import CryptoKit
import Foundation
import KeychainModule
import Security

/// P-256 signing with a private key that lives inside the Secure Enclave.
///
/// The private key never exists in app memory: CryptoKit only hands you an opaque, device-bound
/// `dataRepresentation` blob that is useless on any other device. Typical uses: proving device
/// possession to your backend, signing transactions, or wrapping other keys.
public struct SecureEnclaveSigner: Sendable {
    public enum SignerError: Error, LocalizedError {
        case unavailable
        case accessControl
        /// A key blob is stored but the Secure Enclave can't restore it. It is deliberately not
        /// replaced automatically: a new key means a new public key your backend doesn't know.
        case unusableStoredKey

        public var errorDescription: String? {
            switch self {
            case .unavailable: "The Secure Enclave is not available on this device."
            case .accessControl: "Could not create the key's access-control policy."
            case .unusableStoredKey: "The stored signing key can't be used on this device. Delete it and register a new key with your server."
            }
        }
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    private let privateKey: SecureEnclave.P256.Signing.PrivateKey

    public var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    /// Loads the key blob from the Keychain or creates a new Secure Enclave key.
    ///
    /// A new key is created **only** when no blob is stored. Keychain errors (e.g. locked) and
    /// blobs the Secure Enclave rejects are thrown instead of silently replacing the key, which
    /// would invalidate the public key already registered with your backend.
    public static func loadOrCreate(in store: KeychainStore, account: String) throws -> SecureEnclaveSigner {
        guard isAvailable else { throw SignerError.unavailable }

        do {
            return try load(in: store, account: account)
        } catch KeychainError.itemNotFound {
            // No key yet — create one below.
        }

        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage, // add .biometryCurrentSet to require Face ID for every signature
            nil
        ) else { throw SignerError.accessControl }

        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        do {
            // Insert-only: never overwrite a key another caller stored in the meantime.
            try store.add(key.dataRepresentation, for: account)
            return SecureEnclaveSigner(privateKey: key)
        } catch KeychainError.duplicateItem {
            return try load(in: store, account: account)
        }
    }

    private static func load(in store: KeychainStore, account: String) throws -> SecureEnclaveSigner {
        let blob = try store.data(for: account)
        do {
            return SecureEnclaveSigner(privateKey: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob))
        } catch {
            throw SignerError.unusableStoredKey
        }
    }

    public static func delete(in store: KeychainStore, account: String) throws {
        try store.remove(account)
    }

    /// Returns a DER-encoded ECDSA signature.
    public func sign(_ message: Data) throws -> Data {
        try privateKey.signature(for: message).derRepresentation
    }

    public static func verify(signature: Data, for message: Data, publicKey: P256.Signing.PublicKey) -> Bool {
        guard let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
        return publicKey.isValidSignature(ecdsa, for: message)
    }
}
