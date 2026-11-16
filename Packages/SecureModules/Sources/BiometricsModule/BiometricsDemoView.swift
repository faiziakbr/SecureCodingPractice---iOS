import KeychainModule
import SecurityUI
import SwiftUI

/// Demo: Face ID / Touch ID — the weak "boolean gate" vs. a Keychain item bound to biometrics.
public struct BiometricsDemoView: View {
    @State private var availability: BiometricAvailability?
    @State private var allowPasscode = false
    @State private var secretInput = ""
    @State private var unlockedSecret: String?
    @State private var hasSecret = false
    @State private var enrollmentStatus: SecurityCheck?
    @State private var log: [ConsoleEntry] = []

    private let authenticator = BiometricAuthenticator()
    private let vault = BiometricVault()
    private let settings = KeychainStore(service: "com.securecodingpractice.biometrics-settings")
    private static let enrollmentKey = "biometric-enrollment-state"

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Biometric Authentication",
                    systemImage: availability?.kind.systemImage ?? "faceid",
                    summary: "Use Face ID / Touch ID with LocalAuthentication — and bind secrets to biometrics in the Keychain so the Secure Enclave enforces the check."
                )
            }

            Section {
                if let availability {
                    StatusRow(
                        availability.kind.displayName,
                        detail: availability.isAvailable ? "Available and enrolled" : (availability.unavailableReason ?? "Unavailable"),
                        status: availability.isAvailable ? .passed : .warning
                    )
                }
                if let enrollmentStatus {
                    StatusRow(check: enrollmentStatus)
                    if enrollmentStatus.status == .failed {
                        Button("Accept new biometric set", systemImage: "person.badge.key") {
                            acceptNewEnrollment()
                        }
                    }
                }
            } header: {
                Text("Device")
            } footer: {
                if enrollmentStatus?.status == .failed {
                    Text("A real app would ask for the account password here (verified by your server) before accepting the new set. A biometric match can't do it: the newly added face/finger would pass.")
                }
            }

            Section {
                Toggle("Allow passcode fallback", isOn: $allowPasscode)
                Button("Authenticate", systemImage: availability?.kind.systemImage ?? "faceid") {
                    Task { await simpleAuthenticate() }
                }
            } header: {
                Text("1 · Simple check (UI gate only)")
            } footer: {
                Text("evaluatePolicy returns a Bool. Fine for hiding UI, but on a jailbroken device the result can be hooked. Never guard real secrets with it alone.")
            }

            Section {
                SecureField("Secret to protect", text: $secretInput)
                Button("Store in biometric vault", systemImage: "lock.square.stack") { storeSecret() }
                    .disabled(secretInput.isEmpty)
                Button("Unlock vault", systemImage: "lock.open") {
                    Task { await unlockVault() }
                }
                .disabled(!hasSecret)
                if let unlockedSecret {
                    StatusRow("Vault contents", detail: unlockedSecret, status: .passed)
                }
                Button("Delete vault item", systemImage: "trash", role: .destructive) { deleteSecret() }
                    .disabled(!hasSecret)
            } header: {
                Text("2 · Biometric-bound Keychain item (recommended)")
            } footer: {
                Text("Stored with SecAccessControl(.biometryCurrentSet). The data is only released after a real biometric match, and adding a new face/finger invalidates it.")
            }

            Section("Output") {
                OutputConsole(entries: log)
            }

            Section("Notes") {
                InfoCard(
                    "Info.plist",
                    message: "Face ID requires NSFaceIDUsageDescription in Info.plist, otherwise the app crashes on first use.",
                    status: .warning
                )
                InfoCard(
                    "Testing on the Simulator",
                    message: "Features ▸ Face ID ▸ Enrolled, then use Matching Face / Non-matching Face while the prompt is shown.",
                    status: .info
                )
                CodeComparison(
                    insecure: """
                    if try await context.evaluatePolicy(...) {
                        token = UserDefaults.standard.string(forKey: "token")
                    }
                    """,
                    secure: """
                    let access = SecAccessControlCreateWithFlags(nil,
                        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                        .biometryCurrentSet, nil)
                    // add item with kSecAttrAccessControl: access
                    let token = try await vault.readSecret(reason: "Unlock")
                    """
                )
            }
        }
        .navigationTitle("Biometrics")
        .onAppear(perform: refresh)
    }

    // MARK: Actions

    private func refresh() {
        availability = authenticator.availability()
        hasSecret = vault.hasSecret
        enrollmentStatus = checkEnrollmentChange()
    }

    private func simpleAuthenticate() async {
        do {
            try await authenticator.authenticate(
                reason: "Verify it's you",
                policy: allowPasscode ? .biometricsOrPasscode : .biometricsOnly
            )
            if enrollmentStatus?.status == .failed {
                log.log("Authenticated — but the biometric set changed", "The baseline is NOT updated by a biometric match. Accept the new set after a password check.", .warning)
            } else {
                log.log("Authenticated", "evaluatePolicy succeeded", .passed)
            }
            recordEnrollmentBaselineIfMissing()
        } catch {
            log.log(error: error, title: "Authentication failed")
        }
    }

    private func storeSecret() {
        do {
            try vault.store(Data(secretInput.utf8))
            secretInput = ""
            unlockedSecret = nil
            log.log("Secret stored", "Protected by .biometryCurrentSet", .passed)
            recordEnrollmentBaselineIfMissing()
        } catch {
            log.log(error: error, title: "Store failed")
        }
        refresh()
    }

    private func unlockVault() async {
        do {
            let data = try await vault.readSecret(reason: "Unlock your secure vault")
            unlockedSecret = String(decoding: data, as: UTF8.self)
            log.log("Vault unlocked", "Secret released by the Secure Enclave", .passed)
        } catch {
            unlockedSecret = nil
            log.log(error: error, title: "Unlock failed")
            refresh()
        }
    }

    private func deleteSecret() {
        do {
            try vault.delete()
            unlockedSecret = nil
            log.log("Vault item deleted")
        } catch {
            log.log(error: error, title: "Delete failed")
        }
        refresh()
    }

    // MARK: Enrollment change detection

    /// Trust on first use: records the baseline only if none exists yet. It must never be
    /// overwritten after a biometric success — whoever enrolled the new face/finger would pass.
    private func recordEnrollmentBaselineIfMissing() {
        guard !settings.contains(Self.enrollmentKey) else { return }
        saveEnrollmentState()
    }

    /// Re-baselines after the user proved who they are with a non-biometric factor.
    private func acceptNewEnrollment() {
        // A real app verifies the account password with its server here before continuing.
        saveEnrollmentState()
        log.log("New biometric set accepted", "In production, only after a password check.", .info)
    }

    private func saveEnrollmentState() {
        guard let state = authenticator.currentEnrollmentState() else { return }
        do {
            try settings.set(state, for: Self.enrollmentKey)
        } catch {
            log.log(error: error, title: "Could not save enrollment baseline")
        }
        enrollmentStatus = checkEnrollmentChange()
    }

    private func checkEnrollmentChange() -> SecurityCheck? {
        guard let current = authenticator.currentEnrollmentState() else { return nil }
        guard let saved = try? settings.data(for: Self.enrollmentKey) else {
            return SecurityCheck(id: "enroll", name: "Enrollment baseline", detail: "Authenticate once to record the current biometric set.", status: .info)
        }
        return saved == current
            ? SecurityCheck(id: "enroll", name: "Biometric set unchanged", detail: "Same faces/fingers as last authentication.", status: .passed)
            : SecurityCheck(id: "enroll", name: "Biometric set changed", detail: "A face/finger was added or removed. Require the account password before trusting biometrics again.", status: .failed)
    }
}

#Preview {
    NavigationStack { BiometricsDemoView() }
}
