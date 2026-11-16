import Foundation
import UIKit
import UniformTypeIdentifiers

/// Pasteboard helpers that limit how far copied secrets travel.
@MainActor
public enum SecurePasteboard {
    /// Copies `text` so that it
    /// - stays on this device (`.localOnly` → not synced via Universal Clipboard), and
    /// - is removed automatically after `lifetime`.
    public static func copy(_ text: String, expiresIn lifetime: TimeInterval = 60) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: text]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(lifetime),
            ]
        )
    }

    public static func clear() {
        UIPasteboard.general.items = []
    }
}

/// Writes files with iOS Data Protection so they're encrypted with a key that's unavailable while
/// the device is locked, and keeps them out of iCloud/iTunes backups.
public struct ProtectedFileStore: Sendable {
    public let directory: URL

    public init(folderName: String = "Protected") {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        directory = base.appending(path: folderName, directoryHint: .isDirectory)
    }

    /// Writes atomically with `.completeFileProtection` (NSFileProtectionComplete).
    @discardableResult
    public func write(_ data: Data, named name: String) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var url = directory.appending(path: name)
        try data.write(to: url, options: [.atomic, .completeFileProtection])

        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
        return url
    }

    public func read(named name: String) throws -> Data {
        try Data(contentsOf: directory.appending(path: name))
    }

    public func delete(named name: String) throws {
        try FileManager.default.removeItem(at: directory.appending(path: name))
    }

    /// The data-protection class and backup flag the OS reports for a stored file.
    public func protectionInfo(named name: String) -> (protection: String, excludedFromBackup: Bool)? {
        let url = directory.appending(path: name)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path(percentEncoded: false)) else {
            return nil
        }
        let protection = (attributes[.protectionKey] as? FileProtectionType)?.rawValue ?? "unknown (simulator doesn't enforce data protection)"
        let excluded = (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup) ?? false
        return (protection, excluded)
    }
}
