import SecurityUI
import SwiftUI

/// Demo: input validation, secret-safe logging and insecure vs. secure storage.
public struct SecureInputDemoView: View {
    @State private var username = ""
    @State private var email = ""
    @State private var pin = ""
    @State private var password = ""
    @State private var link = "https://example.com/reset?token=abc"
    @State private var secret = "sk_live_51Hc0ffee"
    @State private var attackerDefaults: String?
    @State private var attackerKeychain: String?
    @State private var log: [ConsoleEntry] = []

    private let comparison = StorageComparison()
    private let logger = SecureLogger(category: "SecureInputDemo")
    private static let allowedHosts: Set<String> = ["example.com", "www.example.com"]

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Secure Input & Storage",
                    systemImage: "text.badge.checkmark",
                    summary: "Validate every input against an allow-list, keep secrets out of logs, and never store them in UserDefaults or plain files."
                )
            }

            Section {
                TextField("Username", text: $username)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                ValidationRow(result: username.isEmpty ? nil : InputValidator.validateUsername(username))

                TextField("Email", text: $email)
                    .keyboardType(.emailAddress)
                    .textContentType(.emailAddress)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                ValidationRow(result: email.isEmpty ? nil : InputValidator.validateEmail(email))

                SecureField("PIN", text: $pin)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                ValidationRow(result: pin.isEmpty ? nil : InputValidator.validatePIN(pin))

                SecureField("Password", text: $password)
                    .textContentType(.newPassword)
                ValidationRow(result: password.isEmpty ? nil : InputValidator.validatePassword(password, username: username))

                TextField("Deep link URL", text: $link)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                ValidationRow(result: link.isEmpty ? nil : InputValidator.validateURL(link, allowedHosts: Self.allowedHosts))
            } header: {
                Text("1 · Allow-list validation")
            } footer: {
                Text("Inputs are normalized (trim, NFC, strip control & zero-width characters) before validation. Allowed link hosts: \(Self.allowedHosts.sorted().joined(separator: ", ")).")
            }

            Section {
                Button("Log a login attempt", systemImage: "text.alignleft") {
                    logger.loginAttempt(username: username.isEmpty ? "alice" : username, success: true)
                    logger.tokenRefreshed(token: secret, expiresIn: 3600)
                    log.log(
                        "Logged with os.Logger",
                        "Open Console.app and filter by category 'SecureInputDemo': the username appears as a hash and the token is never written.",
                        .passed
                    )
                }
                CodeComparison(
                    insecure: """
                    print("Login \\(username) token=\\(token)")
                    """,
                    secure: """
                    logger.info("Login user=\\(username, privacy: .private(mask: .hash))")
                    // and never log tokens/passwords at all
                    """
                )
            } header: {
                Text("2 · Logging")
            }

            Section {
                TextField("Secret (e.g. API token)", text: $secret)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Store in UserDefaults (insecure)", systemImage: "exclamationmark.triangle") {
                    comparison.storeInsecurely(secret)
                    log.log("Stored in UserDefaults", comparison.preferencesPlistPath, .failed)
                }
                Button("Store in Keychain (secure)", systemImage: "key.fill") {
                    do {
                        try comparison.storeSecurely(secret)
                        log.log("Stored in Keychain", "Encrypted by the OS", .passed)
                    } catch {
                        log.log(error: error, title: "Keychain store failed")
                    }
                }
                Button("Inspect like an attacker", systemImage: "magnifyingglass") {
                    attackerDefaults = comparison.attackerViewOfDefaults()
                    attackerKeychain = comparison.attackerViewOfKeychain()
                }
                if let attackerDefaults {
                    StatusRow("UserDefaults plist on disk", detail: attackerDefaults, status: .failed)
                }
                if let attackerKeychain {
                    StatusRow("Keychain", detail: attackerKeychain, status: .passed)
                }
                Button("Clean up", systemImage: "trash", role: .destructive) {
                    comparison.cleanUp()
                    attackerDefaults = nil
                    attackerKeychain = nil
                    log.log("Removed demo secrets from both stores")
                }
            } header: {
                Text("3 · UserDefaults vs Keychain")
            } footer: {
                Text("UserDefaults is a plaintext plist in the app container — visible in unencrypted backups and on jailbroken devices.")
            }

            Section("Output") {
                OutputConsole(entries: log)
            }

            Section("Also remember") {
                InfoCard(
                    "Injection",
                    message: "Never build SQL, predicates, JavaScript or shell strings by concatenating input. Use parameterized SQLite statements, NSPredicate format arguments, and pass data to WKWebView via postMessage/JSON.",
                    status: .warning
                )
                InfoCard(
                    "Sensitive text fields",
                    message: "Use SecureField + textContentType(.password/.newPassword/.oneTimeCode) so the keyboard doesn't learn the value and Password AutoFill works. Disable autocorrection for usernames and tokens.",
                    status: .info
                )
                InfoCard(
                    "Hard-coded secrets",
                    message: "API keys in the binary or Info.plist can be extracted with `strings`. Fetch per-user tokens from your backend after authentication instead.",
                    status: .warning
                )
            }
        }
        .navigationTitle("Secure Input")
    }
}

/// Inline validation feedback under a field.
struct ValidationRow: View {
    let result: ValidationResult?

    var body: some View {
        if let result {
            if result.isValid {
                Label("Valid", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(result.errors, id: \.self) { error in
                        Label(error, systemImage: "xmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
        }
    }
}

#Preview {
    NavigationStack { SecureInputDemoView() }
}
