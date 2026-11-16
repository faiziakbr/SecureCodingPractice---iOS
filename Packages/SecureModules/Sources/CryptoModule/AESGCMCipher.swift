import CryptoKit
import Foundation
import KeychainModule

/// Authenticated encryption with AES-256-GCM.
///
/// GCM gives confidentiality **and** integrity: any modification of the ciphertext, nonce, tag or
/// associated data makes `decrypt` throw instead of returning garbage.
///
/// ```swift
/// let key = try AESGCMCipher.loadOrCreateKey(in: KeychainStore(), account: "notes-key")
/// let cipher = AESGCMCipher(key: key)
/// let sealed = try cipher.encrypt(Data("hello".utf8))   // nonce || ciphertext || tag
/// let plain  = try cipher.decrypt(sealed)
/// ```
public struct AESGCMCipher: Sendable {
    public enum CipherError: Error, LocalizedError {
        case tampered
        case invalidInput

        public var errorDescription: String? {
            switch self {
            case .tampered: "Authentication failed — the ciphertext, nonce, tag or associated data was modified."
            case .invalidInput: "The input is not a valid sealed box."
            }
        }
    }

    private let key: SymmetricKey

    public init(key: SymmetricKey) {
        self.key = key
    }

    /// Encrypts and returns the *combined* representation: 12-byte nonce + ciphertext + 16-byte tag.
    /// A fresh random nonce is generated for every call — never reuse a nonce with the same key.
    public func encrypt(_ plaintext: Data, associatedData: Data? = nil) throws -> Data {
        let box = if let associatedData {
            try AES.GCM.seal(plaintext, using: key, authenticating: associatedData)
        } else {
            try AES.GCM.seal(plaintext, using: key)
        }
        guard let combined = box.combined else { throw CipherError.invalidInput }
        return combined
    }

    public func decrypt(_ combined: Data, associatedData: Data? = nil) throws -> Data {
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: combined)
        } catch {
            throw CipherError.invalidInput
        }
        do {
            return if let associatedData {
                try AES.GCM.open(box, using: key, authenticating: associatedData)
            } else {
                try AES.GCM.open(box, using: key)
            }
        } catch CryptoKitError.authenticationFailure {
            throw CipherError.tampered
        }
    }

    // MARK: Key management

    /// Loads a 256-bit key from the Keychain, creating and storing a random one on first use.
    ///
    /// Never hard-code keys or derive them from constants in the binary — they can be extracted
    /// with `strings`. Generate per-install keys and keep them in the Keychain.
    public static func loadOrCreateKey(in store: KeychainStore, account: String) throws -> SymmetricKey {
        if let data = try? store.data(for: account), data.count == 32 {
            return SymmetricKey(data: data)
        }
        let key = SymmetricKey(size: .bits256)
        try store.set(key.withUnsafeBytes { Data($0) }, for: account)
        return key
    }
}
