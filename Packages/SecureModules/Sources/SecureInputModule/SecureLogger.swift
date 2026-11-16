import Foundation
import os

/// Logging without leaking secrets.
///
/// `print` / `NSLog` write plain text to the device console, which anyone with a cable (or a
/// sysdiagnose) can read. `os.Logger` redacts dynamic values as `<private>` unless you explicitly
/// mark them `.public`, and `.private(mask: .hash)` lets you correlate events without revealing data.
public struct SecureLogger: Sendable {
    private let logger: Logger

    public init(subsystem: String = Bundle.main.bundleIdentifier ?? "SecureCodingPractice", category: String) {
        logger = Logger(subsystem: subsystem, category: category)
    }

    public func loginAttempt(username: String, success: Bool) {
        // username hashed: lets you count attempts per user without logging who they are
        logger.info("Login attempt user=\(username, privacy: .private(mask: .hash)) success=\(success, privacy: .public)")
    }

    public func tokenRefreshed(token: String, expiresIn seconds: Int) {
        // NEVER log the token itself, even privately — log only non-sensitive metadata.
        logger.info("Token refreshed (length=\(token.count, privacy: .public)) expiresIn=\(seconds, privacy: .public)s")
    }

    public func requestFailed(path: String, statusCode: Int) {
        logger.error("Request failed path=\(path, privacy: .public) status=\(statusCode, privacy: .public)")
    }
}
