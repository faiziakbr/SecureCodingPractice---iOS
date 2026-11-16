import SecurityUI
import SwiftUI

/// Demo: SSL / CA public-key pinning with URLSession.
public struct PinningDemoView: View {
    enum Scenario: String, CaseIterable, Identifiable {
        case caPinned = "CA pinned (correct)"
        case wrongPin = "Wrong pin (simulated MITM)"
        case strictUnpinned = "Unpinned host, strict mode"

        var id: String { rawValue }

        var url: URL {
            switch self {
            case .caPinned, .wrongPin: URL(string: "https://www.google.com/generate_204")!
            case .strictUnpinned: URL(string: "https://www.apple.com/")!
            }
        }

        var policy: PinningPolicy {
            switch self {
            case .caPinned:
                PinningPolicy(pinnedHosts: [PinnedHost(host: "google.com", pins: DemoPins.googleCAPins, includesSubdomains: true)])
            case .wrongPin:
                PinningPolicy(pinnedHosts: [PinnedHost(host: "google.com", pins: [DemoPins.bogus], includesSubdomains: true)])
            case .strictUnpinned:
                PinningPolicy(
                    pinnedHosts: [PinnedHost(host: "google.com", pins: DemoPins.googleCAPins, includesSubdomains: true)],
                    rejectUnpinnedHosts: true
                )
            }
        }

        var explanation: String {
            switch self {
            case .caPinned: "Pins the Google Trust Services root CA keys (+ backups). Any valid chain issued under them is accepted."
            case .wrongPin: "Pin set contains only a hash that matches nothing — exactly what happens behind a proxy like Charles/Burp."
            case .strictUnpinned: "apple.com isn't in the pin list and the policy rejects unpinned hosts (allow-list mode)."
            }
        }
    }

    @State private var scenario: Scenario = .caPinned
    @State private var isLoading = false
    @State private var evaluation: PinningEvaluation?
    @State private var requestResult: ConsoleEntry?
    @State private var log: [ConsoleEntry] = []

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "SSL / CA Pinning",
                    systemImage: "pin.fill",
                    summary: "Accept a TLS connection only if the server's certificate chain contains a public key you ship with the app. Defeats MITM with rogue or user-installed CAs."
                )
            }

            Section {
                Picker("Scenario", selection: $scenario) {
                    ForEach(Scenario.allCases) { Text($0.rawValue).tag($0) }
                }
                Text(scenario.explanation).font(.footnote).foregroundStyle(.secondary)
                Text(scenario.url.absoluteString).font(.caption.monospaced())
                Button {
                    Task { await run() }
                } label: {
                    HStack {
                        Label("Send request", systemImage: "paperplane.fill")
                        if isLoading { Spacer(); ProgressView() }
                    }
                }
                .disabled(isLoading)
            } header: {
                Text("Request")
            }

            if let requestResult {
                Section("Result") {
                    StatusRow(requestResult.title, detail: requestResult.detail, status: requestResult.status)
                }
            }

            if let evaluation, !evaluation.chain.isEmpty {
                Section("Validated chain for \(evaluation.host)") {
                    ForEach(evaluation.chain) { certificate in
                        StatusRow(
                            "[\(certificate.index)] \(certificate.subject)",
                            detail: "SPKI SHA-256: \(certificate.spkiHash)",
                            status: certificate.isPinMatch ? .passed : .info
                        )
                    }
                }
            }

            Section("History") {
                OutputConsole(entries: log)
            }

            Section("Best practices") {
                InfoCard(
                    "Pin keys, not certificates — and always ship backups",
                    message: "Pin the SPKI hash of your CA or intermediate (or a leaf key you control), plus at least one backup key that isn't in production yet. Losing all pins bricks networking until users update.",
                    status: .warning
                )
                InfoCard(
                    "Declarative alternative: NSPinnedDomains",
                    message: "Since iOS 14 you can pin in Info.plist under NSAppTransportSecurity ▸ NSPinnedDomains (NSPinnedCAIdentities / NSPinnedLeafIdentities). The OS then enforces it for all URLSession traffic.",
                    status: .info
                )
                InfoCard(
                    "Private PKI",
                    message: "If your backend uses a private CA, bundle its DER certificate and call SecTrustSetAnchorCertificates + SecTrustSetAnchorCertificatesOnly before evaluation.",
                    status: .info
                )
                CodeComparison(
                    insecure: """
                    // Disables ALL TLS validation — never ship this
                    completionHandler(.useCredential,
                        URLCredential(trust: challenge.protectionSpace.serverTrust!))
                    """,
                    secure: """
                    guard SecTrustEvaluateWithError(trust, nil) else { cancel() }
                    let chain = SecTrustCopyCertificateChain(trust) as! [SecCertificate]
                    let ok = chain.contains { pins.contains(SPKIHasher.sha256Base64(for: $0)!) }
                    ok ? useCredential() : cancel()
                    """
                )
            }
        }
        .navigationTitle("SSL Pinning")
    }

    private func run() async {
        isLoading = true
        defer { isLoading = false }

        let recorder = PinningEvaluationRecorder()
        let session = PinnedSession.make(policy: scenario.policy, recorder: recorder)
        defer { session.finishTasksAndInvalidate() }

        let result: ConsoleEntry
        do {
            let (_, response) = try await session.data(from: scenario.url)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            result = ConsoleEntry("Connection allowed", detail: "HTTP \(status) from \(scenario.url.host() ?? "")", status: .passed)
        } catch let error as URLError where error.code == .cancelled {
            result = ConsoleEntry("Connection blocked", detail: "Pinning rejected the server (challenge cancelled).", status: .failed)
        } catch {
            result = ConsoleEntry("Request failed", detail: error.localizedDescription, status: .failed)
        }

        evaluation = recorder.evaluations.last
        requestResult = result
        let outcome = evaluation.map { describe($0.outcome) } ?? "no trust challenge (connection reused?)"
        log.log("\(scenario.rawValue): \(result.title)", "Pinning outcome: \(outcome)", result.status)
    }

    private func describe(_ outcome: PinningEvaluation.Outcome) -> String {
        switch outcome {
        case .pinMatched: "pin matched"
        case .pinMismatch: "no pinned key in chain"
        case .trustFailed(let message): "trust failed — \(message)"
        case .notPinned: "host not pinned, default handling"
        case .rejectedUnpinned: "host not pinned, rejected by strict policy"
        }
    }
}

#Preview {
    NavigationStack { PinningDemoView() }
}
