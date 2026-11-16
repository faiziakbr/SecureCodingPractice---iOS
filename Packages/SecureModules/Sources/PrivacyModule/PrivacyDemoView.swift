import SecurityUI
import SwiftUI
import UIKit

/// Demo: protecting sensitive data on screen, on the pasteboard and on disk.
public struct PrivacyDemoView: View {
    @State private var revealCard = false
    @State private var screenshotCount = 0
    @State private var isCaptured = false
    @State private var fileText = "Medical note: allergic to penicillin"
    @State private var log: [ConsoleEntry] = []

    private let fileStore = ProtectedFileStore()
    private static let fileName = "secret-note.txt"
    private static let cardNumber = "4111 1111 1111 1111"

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Screen & Data Privacy",
                    systemImage: "eye.slash.fill",
                    summary: "Sensitive data leaks through app-switcher snapshots, screen recordings, the clipboard and unprotected files. Close each of those channels."
                )
            }

            Section {
                StatusRow(
                    "App-switcher protection is ON",
                    detail: "Swipe up to the app switcher: the whole app is covered by .privacyProtected() applied at the root.",
                    status: .passed
                )
            } header: {
                Text("1 · Background snapshot")
            }

            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Card number").font(.caption).foregroundStyle(.secondary)
                    Text(revealCard ? Self.cardNumber : "•••• •••• •••• 1111")
                        .font(.title3.monospaced())
                        .privacySensitive()
                    Toggle("Reveal", isOn: $revealCard)
                }
                .padding(.vertical, 4)
                .screenCaptureProtected()

                StatusRow(
                    isCaptured ? "Screen is being captured" : "Screen not captured",
                    detail: "Start a screen recording from Control Center — the card above is covered while recording.",
                    status: isCaptured ? .warning : .passed
                )
                StatusRow(
                    "Screenshots taken: \(screenshotCount)",
                    detail: "iOS can't block screenshots, but you get notified after one is taken — warn the user or log it.",
                    status: screenshotCount > 0 ? .warning : .info
                )
            } header: {
                Text("2 · Screen recording & screenshots")
            }

            Section {
                Button("Copy card number (local only, expires in 30 s)", systemImage: "doc.on.clipboard") {
                    SecurePasteboard.copy(Self.cardNumber, expiresIn: 30)
                    log.log("Copied with .localOnly + .expirationDate", "Not synced to other devices via Universal Clipboard; removed after 30 s.", .passed)
                }
                Button("Clear pasteboard", systemImage: "clear") {
                    SecurePasteboard.clear()
                    log.log("Pasteboard cleared")
                }
            } header: {
                Text("3 · Clipboard")
            } footer: {
                Text("Other apps can read the general pasteboard. For OTPs and passwords, prefer not offering copy at all.")
            }

            Section {
                TextField("Sensitive text", text: $fileText, axis: .vertical)
                Button("Write protected file", systemImage: "externaldrive.badge.checkmark", action: writeFile)
                Button("Read protected file", systemImage: "doc.text.magnifyingglass", action: readFile)
                Button("Delete file", systemImage: "trash", role: .destructive, action: deleteFile)
            } header: {
                Text("4 · Data Protection on disk")
            } footer: {
                Text("Written with .completeFileProtection: encrypted with a key that is evicted ~10 s after the device locks. Also excluded from backups.")
            }

            Section("Output") {
                OutputConsole(entries: log)
            }

            Section("More tips") {
                InfoCard(
                    "Secure text fields",
                    message: "Use SecureField for secrets — iOS hides it in screenshots/recordings of the keyboard and disables autocorrect learning and copy.",
                    status: .info
                )
                InfoCard(
                    "Clear sensitive state on background",
                    message: "Use the scenePhase change to .background to drop decrypted data from memory, invalidate short-lived sessions and require re-authentication on return.",
                    status: .info
                )
                InfoCard(
                    "Screenshot blocking hacks",
                    message: "Embedding content in a secure UITextField's layer to hide it from screenshots relies on private view hierarchy behavior and can break with any iOS update. Prefer the documented techniques above.",
                    status: .warning
                )
            }
        }
        .navigationTitle("Privacy")
        .onAppear { isCaptured = ScreenCaptureState.isCaptured }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            screenshotCount += 1
            log.log("Screenshot detected", "Consider warning the user that sensitive data may now be in Photos.", .warning)
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            isCaptured = ScreenCaptureState.isCaptured
            log.log(isCaptured ? "Screen capture started" : "Screen capture stopped", "", isCaptured ? .warning : .info)
        }
    }

    private func writeFile() {
        do {
            let url = try fileStore.write(Data(fileText.utf8), named: Self.fileName)
            let info = fileStore.protectionInfo(named: Self.fileName)
            log.log(
                "Wrote \(url.lastPathComponent)",
                "Protection: \(info?.protection ?? "?")\nExcluded from backup: \(info?.excludedFromBackup ?? false)",
                .passed
            )
        } catch {
            log.log(error: error, title: "Write failed")
        }
    }

    private func readFile() {
        do {
            let text = String(decoding: try fileStore.read(named: Self.fileName), as: UTF8.self)
            log.log("Read protected file", text, .passed)
        } catch {
            log.log(error: error, title: "Read failed")
        }
    }

    private func deleteFile() {
        do {
            try fileStore.delete(named: Self.fileName)
            log.log("File deleted")
        } catch {
            log.log(error: error, title: "Delete failed")
        }
    }
}

#Preview {
    NavigationStack { PrivacyDemoView() }
}
