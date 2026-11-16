import SecurityUI
import SwiftUI

/// Demo: save, read, update and delete secrets in the iOS Keychain.
public struct KeychainDemoView: View {
    @State private var key = "accessToken"
    @State private var value = ""
    @State private var accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly
    @State private var storedKeys: [String] = []
    @State private var log: [ConsoleEntry] = []

    private static let demoService = "com.securecodingpractice.keychain-demo"

    public init() {}

    private var store: KeychainStore {
        KeychainStore(service: Self.demoService, accessibility: accessibility)
    }

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Keychain Storage",
                    systemImage: "key.fill",
                    summary: "The Keychain is an encrypted database managed by the OS and protected by the Secure Enclave. Store every secret here — tokens, passwords, keys."
                )
            }

            Section("Item") {
                TextField("Key (account)", text: $key)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                SecureField("Secret value", text: $value)
                    .textContentType(.password)
                Picker("Accessibility", selection: $accessibility) {
                    ForEach(KeychainAccessibility.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .pickerStyle(.navigationLink)
            }

            Section("Actions") {
                Button("Save / Update", systemImage: "square.and.arrow.down", action: save)
                    .disabled(key.isEmpty || value.isEmpty)
                Button("Read", systemImage: "eye", action: read)
                    .disabled(key.isEmpty)
                Button("Delete", systemImage: "trash", role: .destructive, action: delete)
                    .disabled(key.isEmpty)
                Button("Delete all demo items", systemImage: "trash.slash", role: .destructive, action: deleteAll)
            }

            Section("Stored keys (\(storedKeys.count))") {
                if storedKeys.isEmpty {
                    Text("Nothing stored yet.").foregroundStyle(.secondary)
                } else {
                    ForEach(storedKeys, id: \.self) { storedKey in
                        Button {
                            key = storedKey
                            read()
                        } label: {
                            Label(storedKey, systemImage: "lock.fill")
                        }
                    }
                }
            }

            Section("Output") {
                OutputConsole(entries: log)
            }

            Section("Why it matters") {
                InfoCard(
                    "Pick the right accessibility class",
                    message: "Use a *ThisDeviceOnly class so secrets never leave the device in a backup. kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly is the strongest: items are destroyed if the passcode is removed.",
                    status: .passed
                )
                InfoCard(
                    "Keychain items survive app deletion",
                    message: "Clear stale items on first launch after reinstall (e.g. track a 'hasLaunched' flag in UserDefaults) so a new user doesn't inherit old credentials.",
                    status: .warning
                )
                CodeComparison(
                    insecure: """
                    // Stored in a plaintext plist inside the app container
                    UserDefaults.standard.set(token, forKey: "token")
                    """,
                    secure: """
                    let store = KeychainStore(accessibility: .whenUnlockedThisDeviceOnly)
                    try store.set(token, for: "token")
                    let token = try store.string(for: "token")
                    """
                )
            }
        }
        .navigationTitle("Keychain")
        .onAppear(perform: refreshKeys)
    }

    // MARK: Actions

    private func save() {
        do {
            try store.set(value, for: key)
            log.log("Saved '\(key)'", "Accessibility: \(accessibility.title)", .passed)
            value = ""
            refreshKeys()
        } catch {
            log.log(error: error, title: "Save failed")
        }
    }

    private func read() {
        do {
            let secret = try store.string(for: key)
            log.log("Read '\(key)'", "Value: \(secret)", .passed)
        } catch {
            log.log(error: error, title: "Read '\(key)' failed")
        }
    }

    private func delete() {
        do {
            try store.remove(key)
            log.log("Deleted '\(key)'", "", .info)
            refreshKeys()
        } catch {
            log.log(error: error, title: "Delete failed")
        }
    }

    private func deleteAll() {
        do {
            try store.removeAll()
            log.log("Deleted all demo items", "", .info)
            refreshKeys()
        } catch {
            log.log(error: error, title: "Delete all failed")
        }
    }

    private func refreshKeys() {
        storedKeys = (try? store.allKeys()) ?? []
    }
}

#Preview {
    NavigationStack { KeychainDemoView() }
}
