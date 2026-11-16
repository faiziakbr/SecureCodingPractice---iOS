import CryptoKit
import Foundation

/// Hashing, message authentication and key derivation helpers.
public enum Hashing {
    /// SHA-256 as lowercase hex. Use for integrity/fingerprints — **not** for passwords.
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).hexString
    }

    /// HMAC-SHA256 tag proving the message came from someone holding `key`.
    public static func hmacSHA256(_ message: Data, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    /// Constant-time verification — never compare MACs with `==` on raw bytes in custom code.
    public static func verifyHMAC(_ tag: Data, for message: Data, key: SymmetricKey) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: message, using: key)
    }

    /// Derives a purpose-specific subkey from a master key with HKDF-SHA256.
    /// Use different `info` strings for different purposes (e.g. "file-encryption", "api-signing").
    public static func deriveKey(from master: SymmetricKey, salt: Data, info: String, byteCount: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: byteCount
        )
    }
}

extension Digest {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

public extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
