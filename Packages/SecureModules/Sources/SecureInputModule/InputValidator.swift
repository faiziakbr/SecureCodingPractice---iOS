import Foundation

/// Result of validating user input.
public struct ValidationResult: Sendable, Equatable {
    /// The normalized value that was validated — use this, not the raw input.
    public let sanitized: String
    public let errors: [String]

    public var isValid: Bool { errors.isEmpty }
}

/// Allow-list based input validation.
///
/// Principles:
/// - **Normalize first** (trim, Unicode NFC, strip control characters), then validate the normalized value.
/// - **Allow-list** what is valid instead of trying to block "bad" characters.
/// - **Bound lengths** to stop resource exhaustion and buffer-style issues downstream.
/// - Client-side validation is UX. The server must validate again.
public enum InputValidator {
    /// Trims whitespace, applies Unicode canonical composition and removes control/format characters
    /// (e.g. zero-width spaces, right-to-left override) that are used for spoofing.
    public static func normalize(_ input: String) -> String {
        let composed = input.precomposedStringWithCanonicalMapping
        let filtered = composed.unicodeScalars.filter { scalar in
            !CharacterSet.controlCharacters.contains(scalar) && scalar.properties.generalCategory != .format
        }
        return String(String.UnicodeScalarView(filtered)).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func validateUsername(_ input: String) -> ValidationResult {
        let value = normalize(input)
        var errors: [String] = []
        if !(3...20).contains(value.count) { errors.append("Must be 3–20 characters.") }
        if value.wholeMatch(of: /[A-Za-z0-9._]+/) == nil {
            errors.append("Only letters, digits, '.' and '_' are allowed.")
        }
        if value.hasPrefix(".") || value.hasSuffix(".") { errors.append("Can't start or end with '.'.") }
        return ValidationResult(sanitized: value, errors: errors)
    }

    public static func validateEmail(_ input: String) -> ValidationResult {
        let value = normalize(input).lowercased()
        var errors: [String] = []
        if value.count > 254 { errors.append("Too long (max 254 characters).") }
        if value.wholeMatch(of: /[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}/) == nil {
            errors.append("Not a valid email address.")
        }
        return ValidationResult(sanitized: value, errors: errors)
    }

    public static func validatePIN(_ input: String) -> ValidationResult {
        let value = normalize(input)
        var errors: [String] = []
        if value.wholeMatch(of: /[0-9]{4,6}/) == nil {
            errors.append("Must be 4–6 digits.")
        } else {
            let digits = value.compactMap(\.wholeNumberValue)
            if Set(digits).count == 1 { errors.append("All digits are the same.") }
            let deltas = zip(digits, digits.dropFirst()).map { $1 - $0 }
            if Set(deltas).count == 1, let delta = deltas.first, abs(delta) == 1 {
                errors.append("Sequential PINs (1234, 4321) are too easy to guess.")
            }
        }
        return ValidationResult(sanitized: value, errors: errors)
    }

    /// Passwords are **not** normalized beyond NFC — every character the user typed matters.
    public static func validatePassword(_ input: String, username: String? = nil) -> ValidationResult {
        let value = input.precomposedStringWithCanonicalMapping
        var errors: [String] = []
        if value.count < 12 { errors.append("Use at least 12 characters.") }
        if value.count > 128 { errors.append("Too long (max 128 characters).") }
        if value.rangeOfCharacter(from: .lowercaseLetters) == nil { errors.append("Add a lowercase letter.") }
        if value.rangeOfCharacter(from: .uppercaseLetters) == nil { errors.append("Add an uppercase letter.") }
        if value.rangeOfCharacter(from: .decimalDigits) == nil { errors.append("Add a digit.") }
        if value.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) == nil { errors.append("Add a symbol.") }
        if let username, !username.isEmpty, value.lowercased().contains(username.lowercased()) {
            errors.append("Must not contain your username.")
        }
        return ValidationResult(sanitized: value, errors: errors)
    }

    /// Validates a URL from untrusted input (deep links, QR codes, server responses) against an allow-list.
    public static func validateURL(_ input: String, allowedHosts: Set<String>) -> ValidationResult {
        let value = normalize(input)
        var errors: [String] = []
        guard let components = URLComponents(string: value), let host = components.host?.lowercased() else {
            return ValidationResult(sanitized: value, errors: ["Not a valid URL."])
        }
        if components.scheme?.lowercased() != "https" { errors.append("Only https:// URLs are allowed.") }
        if !allowedHosts.contains(host) { errors.append("Host '\(host)' is not on the allow-list.") }
        if components.user != nil || components.password != nil { errors.append("Credentials in URLs are not allowed.") }
        return ValidationResult(sanitized: value, errors: errors)
    }
}
