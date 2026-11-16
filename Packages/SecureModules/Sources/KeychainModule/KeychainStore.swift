import Foundation
import Security

/// Errors surfaced by `KeychainStore`, mapped from Security framework `OSStatus` codes.
public enum KeychainError: Error, LocalizedError, Equatable {
    case itemNotFound
    case duplicateItem
    case invalidData
    case authenticationFailed
    case userCanceled
    case interactionNotAllowed
    case missingEntitlement
    case unhandled(OSStatus)

    public init(status: OSStatus) {
        switch status {
        case errSecItemNotFound: self = .itemNotFound
        case errSecDuplicateItem: self = .duplicateItem
        case errSecAuthFailed: self = .authenticationFailed
        case errSecUserCanceled: self = .userCanceled
        case errSecInteractionNotAllowed: self = .interactionNotAllowed
        case errSecMissingEntitlement: self = .missingEntitlement
        default: self = .unhandled(status)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .itemNotFound: "No item found for this key."
        case .duplicateItem: "An item with this key already exists."
        case .invalidData: "The stored data could not be decoded."
        case .authenticationFailed: "Authentication failed (wrong credentials, or no device passcode set)."
        case .userCanceled: "The user canceled authentication."
        case .interactionNotAllowed: "The keychain is locked or user interaction is not allowed right now."
        case .missingEntitlement: "Missing keychain entitlement (errSecMissingEntitlement)."
        case .unhandled(let status):
            (SecCopyErrorMessageString(status, nil) as String?).map { "\($0) (\(status))" } ?? "Keychain error \(status)."
        }
    }
}

/// When a keychain item may be read. Prefer the most restrictive option that works for your use case.
public enum KeychainAccessibility: String, CaseIterable, Sendable, Identifiable {
    /// Readable only while unlocked, never migrated to another device via backup. **Recommended default.**
    case whenUnlockedThisDeviceOnly
    /// Like above, but the item is deleted if the user removes the device passcode. Strongest option.
    case whenPasscodeSetThisDeviceOnly
    /// Readable after first unlock until reboot — use for background tasks (e.g. refresh tokens).
    case afterFirstUnlockThisDeviceOnly
    /// Readable while unlocked; *is* included in encrypted backups and can move to a new device.
    case whenUnlocked

    public var id: String { rawValue }

    public var value: CFString {
        switch self {
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        }
    }

    public var title: String {
        switch self {
        case .whenUnlockedThisDeviceOnly: "When unlocked (this device only)"
        case .whenPasscodeSetThisDeviceOnly: "When passcode set (this device only)"
        case .afterFirstUnlockThisDeviceOnly: "After first unlock (this device only)"
        case .whenUnlocked: "When unlocked (migrates with backups)"
        }
    }
}

/// A thin, type-safe wrapper around generic-password keychain items.
///
/// ```swift
/// let store = KeychainStore(service: "com.example.auth")
/// try store.set("eyJhbGciOi...", for: "accessToken")
/// let token = try store.string(for: "accessToken")
/// try store.remove("accessToken")
/// ```
///
/// Secrets (tokens, passwords, encryption keys) belong here — never in `UserDefaults`,
/// plist files, Core Data, or source code.
public struct KeychainStore: Sendable {
    public let service: String
    public let accessGroup: String?
    public let accessibility: KeychainAccessibility

    public init(
        service: String = (Bundle.main.bundleIdentifier ?? "SecureCodingPractice") + ".keychain",
        accessGroup: String? = nil,
        accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessibility = accessibility
    }

    // MARK: Data

    /// Inserts or replaces the value for `key`.
    public func set(_ data: Data, for key: String) throws {
        var addQuery = baseQuery(for: key)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessibility.value

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            // Upsert: update the existing item (including its accessibility class).
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessibility.value,
            ]
            let updateStatus = SecItemUpdate(baseQuery(for: key) as CFDictionary, attributes as CFDictionary)
            guard updateStatus == errSecSuccess else { throw KeychainError(status: updateStatus) }
        default:
            throw KeychainError(status: status)
        }
    }

    /// Inserts the value for `key` only if no item exists yet; throws `KeychainError.duplicateItem`
    /// otherwise. Use this instead of `set` when overwriting would destroy something (e.g. a key).
    public func add(_ data: Data, for key: String) throws {
        var addQuery = baseQuery(for: key)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessibility.value

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    /// Returns the stored data, or throws `KeychainError.itemNotFound`.
    public func data(for key: String) throws -> Data {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        guard let data = result as? Data else { throw KeychainError.invalidData }
        return data
    }

    // MARK: String

    public func set(_ string: String, for key: String) throws {
        try set(Data(string.utf8), for: key)
    }

    public func string(for key: String) throws -> String {
        guard let string = String(data: try data(for: key), encoding: .utf8) else {
            throw KeychainError.invalidData
        }
        return string
    }

    // MARK: Codable

    public func setCodable<T: Encodable>(_ value: T, for key: String) throws {
        try set(try JSONEncoder().encode(value), for: key)
    }

    public func codable<T: Decodable>(_ type: T.Type, for key: String) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: try data(for: key))
        } catch let error as KeychainError {
            throw error
        } catch {
            throw KeychainError.invalidData
        }
    }

    // MARK: Housekeeping

    public func contains(_ key: String) -> Bool {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = false
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Deletes the value for `key`. Deleting a missing key is not an error.
    public func remove(_ key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    /// Deletes every item stored under this store's `service`.
    public func removeAll() throws {
        let status = SecItemDelete(serviceQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    /// All account names (keys) stored under this service. Values are not returned.
    public func allKeys() throws -> [String] {
        var query = serviceQuery()
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        let items = result as? [[String: Any]] ?? []
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    // MARK: Queries

    private func serviceQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            // Never sync secrets to iCloud Keychain unless that is an explicit product decision.
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query = serviceQuery()
        query[kSecAttrAccount as String] = key
        return query
    }
}
