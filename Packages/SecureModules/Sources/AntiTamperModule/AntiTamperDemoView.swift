import SecurityUI
import SwiftUI

/// Demo: anti-debugging, runtime-injection and app-integrity checks.
public struct AntiTamperDemoView: View {
    @State private var checks: [SecurityCheck] = []
    @State private var isRunning = false
    @State private var confirmDenyAttach = false
    @State private var denyAttachResult: SecurityCheck?

    private let expectedBundleIdentifier: String

    /// - Parameter expectedBundleIdentifier: the bundle ID your release build must have.
    public init(expectedBundleIdentifier: String) {
        self.expectedBundleIdentifier = expectedBundleIdentifier
    }

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "Anti-Debug & Tamper",
                    systemImage: "ant.fill",
                    summary: "Attackers debug, hook (Frida) or repackage apps to bypass checks and steal data. These checks make that harder and give your backend a signal."
                )
            }

            Section {
                Button {
                    Task { await runChecks() }
                } label: {
                    HStack {
                        Label("Run checks", systemImage: "waveform.path.ecg")
                        if isRunning { Spacer(); ProgressView() }
                    }
                }
                .disabled(isRunning)
                if !checks.isEmpty {
                    HStack {
                        Text("Result").font(.subheadline.weight(.semibold))
                        Spacer()
                        RiskBadge(RiskLevel(checks: checks))
                    }
                }
            }

            if !checks.isEmpty {
                Section("Checks") {
                    ForEach(checks) { StatusRow(check: $0) }
                }
            }

            Section {
                Button("Deny debugger attachment", systemImage: "hand.raised.fill", role: .destructive) {
                    confirmDenyAttach = true
                }
                if let denyAttachResult {
                    StatusRow(check: denyAttachResult)
                }
            } header: {
                Text("ptrace(PT_DENY_ATTACH)")
            } footer: {
                Text("If Xcode's debugger is attached, the app will exit immediately. In a real app call DebuggerDetector.denyDebuggerAttachment() at launch in Release builds only.")
            }

            Section("Notes") {
                InfoCard(
                    "Everything client-side can be patched",
                    message: "Anti-tamper raises the cost of an attack; it doesn't make it impossible. Keep secrets and business rules on the server and use App Attest to verify app integrity cryptographically.",
                    status: .warning
                )
                InfoCard(
                    "Harden the binary",
                    message: "Strip symbols in Release, avoid descriptive names for security functions, duplicate checks in several places, and react silently (e.g. report to backend) instead of an obvious alert an attacker can trace.",
                    status: .info
                )
                CodeBlock(
                    label: "Detecting a debugger",
                    code: """
                    var info = kinfo_proc()
                    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
                    var size = MemoryLayout<kinfo_proc>.stride
                    sysctl(&mib, 4, &info, &size, nil, 0)
                    let attached = (info.kp_proc.p_flag & P_TRACED) != 0
                    """
                )
            }
        }
        .navigationTitle("Anti-Tamper")
        .task { await runChecks() }
        .confirmationDialog(
            "Deny debugger attachment?",
            isPresented: $confirmDenyAttach,
            titleVisibility: .visible
        ) {
            Button("Call PT_DENY_ATTACH", role: .destructive) {
                let success = DebuggerDetector.denyDebuggerAttachment()
                denyAttachResult = SecurityCheck(
                    id: "deny",
                    name: success ? "Debugger attachment denied" : "ptrace unavailable",
                    detail: success ? "New debugger attach attempts will now fail for this process." : "Could not resolve ptrace via dlsym.",
                    status: success ? .passed : .warning
                )
            }
        } message: {
            Text("If a debugger is attached right now (running from Xcode), the app will terminate.")
        }
    }

    private func runChecks() async {
        isRunning = true
        checks = await Self.collect(expectedBundleIdentifier: expectedBundleIdentifier)
        isRunning = false
    }

    @concurrent
    private static func collect(expectedBundleIdentifier: String) async -> [SecurityCheck] {
        [DebuggerDetector.check()]
            + InjectionDetector().run()
            + IntegrityChecker(expectedBundleIdentifier: expectedBundleIdentifier).run()
    }
}

#Preview {
    NavigationStack { AntiTamperDemoView(expectedBundleIdentifier: "com.example.app") }
}
