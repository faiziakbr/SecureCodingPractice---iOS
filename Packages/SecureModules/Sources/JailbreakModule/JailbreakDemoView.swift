import SecurityUI
import SwiftUI

/// Demo: layered jailbreak / root detection.
public struct JailbreakDemoView: View {
    @State private var report: JailbreakReport?
    @State private var isRunning = false

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Jailbreak Detection",
                    systemImage: "lock.trianglebadge.exclamationmark.fill",
                    summary: "A jailbroken device has no sandbox guarantees: other code can read your app's memory, files and Keychain, and hook any function. Detect it and reduce risk."
                )
            }

            Section {
                Button {
                    Task { await runChecks() }
                } label: {
                    HStack {
                        Label("Run checks", systemImage: "magnifyingglass")
                        if isRunning { Spacer(); ProgressView() }
                    }
                }
                .disabled(isRunning)
                if let report {
                    HStack {
                        Text(report.isLikelyJailbroken ? "Device looks compromised" : "No jailbreak indicators")
                            .font(.subheadline.weight(.semibold))
                        Spacer()
                        RiskBadge(report.risk)
                    }
                }
            }

            if let report {
                Section("Checks") {
                    ForEach(report.checks) { StatusRow(check: $0) }
                }
            }

            Section("How to respond") {
                InfoCard(
                    "Treat it as a risk signal",
                    message: "Every client-side check can be bypassed by a determined attacker (hiding tweaks hook the very APIs used here). Report the result to your backend and decide there: step-up auth, limit features, or flag the session.",
                    status: .warning
                )
                InfoCard(
                    "Use App Attest for real assurance",
                    message: "DCAppAttestService lets your server cryptographically verify requests come from a genuine, unmodified instance of your app on a real Apple device.",
                    status: .passed
                )
                InfoCard(
                    "Layer and vary the checks",
                    message: "Run checks at several points (launch, login, before payments), inline them in different places, and combine with anti-debug and injection checks from the Anti-Tamper module.",
                    status: .info
                )
            }
        }
        .navigationTitle("Jailbreak Detection")
        .task { await runChecks() }
    }

    private func runChecks() async {
        isRunning = true
        report = await Self.detect()
        isRunning = false
    }

    // File-system probing is blocking I/O, so do it off the main actor.
    @concurrent
    private static func detect() async -> JailbreakReport {
        JailbreakDetector().run()
    }
}

#Preview {
    NavigationStack { JailbreakDemoView() }
}
