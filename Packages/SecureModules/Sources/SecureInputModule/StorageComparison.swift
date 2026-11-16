import Foundation
import KeychainModule

/// Shows what an attacker with file-system access (jailbreak, unencrypted backup, forensic tool)
/// sees for a secret stored in UserDefaults vs. the Keychain.
public struct StorageComparison: Sendable {
    public static let defaultsKey = "insecure_demo_api_token"
    public static let keychainKey = "secure_demo_api_token"

    private let keychain = KeychainStore(service: "com.securecodingpractice.storage-demo")

    public init() {}

    /// ❌ Plaintext in Library/Preferences/<bundle-id>.plist
    public func storeInsecurely(_ secret: String) {
        UserDefaults.standard.set(secret, forKey: Self.defaultsKey)
    }

    /// ✅ Encrypted by the OS, gated by the device passcode, excluded from other apps.
    public func storeSecurely(_ secret: String) throws {
        try keychain.set(secret, for: Self.keychainKey)
    }

    /// Path of the preferences plist inside the app container.
    public var preferencesPlistPath: String {
        let bundleID = Bundle.main.bundleIdentifier ?? "unknown"
        return NSHomeDirectory() + "/Library/Preferences/\(bundleID).plist"
    }

    /// Reads the raw plist from disk the way an attacker would — no APIs, just the file.
    /// cfprefsd writes asynchronously, so a just-written value may take a moment to appear on disk.
    public func attackerViewOfDefaults() -> String {
        guard
            let data = FileManager.default.contents(atPath: preferencesPlistPath),
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else {
            return "Plist not on disk yet (cfprefsd writes lazily). In-memory value: \(UserDefaults.standard.string(forKey: Self.defaultsKey) ?? "none")"
        }
        let value = plist[Self.defaultsKey] as? String ?? "<not present>"
        return "\(Self.defaultsKey) = \"\(value)\"  ← readable in plain text"
    }

    /// Keychain items live in an encrypted SQLite database outside the app container (keychain-2.db),
    /// with each item encrypted by keys protected by the Secure Enclave.
    public func attackerViewOfKeychain() -> String {
        keychain.contains(Self.keychainKey)
            ? "Item exists, but its value is encrypted in /private/var/Keychains/keychain-2.db and not in the app container."
            : "No Keychain item stored yet."
    }

    public func cleanUp() {
        UserDefaults.standard.removeObject(forKey: Self.defaultsKey)
        try? keychain.remove(Self.keychainKey)
    }
}
