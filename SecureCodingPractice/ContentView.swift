//
//  ContentView.swift
//  SecureCodingPractice
//
//  Created by Faizan on 16/11/2026.
//

import AntiTamperModule
import JailbreakModule
import SecurityUI
import SwiftUI

struct ContentView: View {
    @State private var deviceChecks: [SecurityCheck] = []

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if deviceChecks.isEmpty {
                        ProgressView("Checking device…")
                    } else {
                        HStack {
                            Text("Device security").font(.headline)
                            Spacer()
                            RiskBadge(RiskLevel(checks: deviceChecks))
                        }
                        ForEach(deviceChecks) { StatusRow(check: $0) }
                    }
                } footer: {
                    Text("Quick launch-time check. Open Jailbreak Detection or Anti-Debug for details.")
                }

                Section("Modules") {
                    ForEach(SecureModule.allCases) { module in
                        NavigationLink(value: module) {
                            ModuleRow(module: module)
                        }
                    }
                }
            }
            .navigationTitle("Secure Coding")
            .navigationDestination(for: SecureModule.self) { module in
                module.destination
            }
            .task { await runDeviceChecks() }
            .refreshable { await runDeviceChecks() }
        }
    }

    private func runDeviceChecks() async {
        deviceChecks = await Self.quickChecks()
    }

    @concurrent
    private static func quickChecks() async -> [SecurityCheck] {
        let jailbreak = JailbreakDetector().run()
        let summary = SecurityCheck(
            id: "jailbreak-summary",
            name: jailbreak.isSimulator ? "Jailbreak checks (Simulator)" : "Jailbreak checks",
            detail: jailbreak.isSimulator
                ? "Not meaningful on the Simulator."
                : (jailbreak.isLikelyJailbroken ? "Jailbreak indicators found." : "No jailbreak indicators."),
            status: jailbreak.isSimulator ? .warning : (jailbreak.isLikelyJailbroken ? .failed : .passed)
        )
        return [summary, DebuggerDetector.check()]
    }
}

private struct ModuleRow: View {
    let module: SecureModule

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: module.systemImage)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 34, height: 34)
                .background(module.tint.gradient, in: .rect(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(module.title).font(.body.weight(.medium))
                Text(module.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 2)
    }
}

#Preview {
    ContentView()
}
