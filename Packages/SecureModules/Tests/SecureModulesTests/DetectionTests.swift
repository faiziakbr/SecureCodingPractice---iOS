import Foundation
import SecurityCore
import Testing
@testable import AntiTamperModule
@testable import JailbreakModule

/// In-memory file system for deterministic jailbreak-detector tests.
struct FakeFileSystem: FileSystemProbing {
    var existing: Set<String> = []
    var symlinks: Set<String> = []
    var writable = false

    func fileExists(atPath path: String) -> Bool { existing.contains(path) }
    func isSymbolicLink(atPath path: String) -> Bool { symlinks.contains(path) }
    func canWrite(toPath path: String) -> Bool { writable }
}

@Suite("Jailbreak detection")
struct JailbreakDetectorTests {
    private func detector(
        fileSystem: FakeFileSystem = FakeFileSystem(),
        images: [String] = ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/UIKit.framework/UIKit"],
        env: [String: String] = [:],
        isSimulator: Bool = false
    ) -> JailbreakDetector {
        JailbreakDetector(
            fileSystem: fileSystem,
            loadedImages: { images },
            environment: { env[$0] },
            isSimulator: isSimulator
        )
    }

    @Test func cleanDeviceHasLowRisk() {
        let report = detector().run()
        #expect(!report.isLikelyJailbroken)
        #expect(report.risk == .low)
        #expect(report.checks.allSatisfy { $0.status == .passed })
    }

    @Test func rootlessJailbreakFilesAreDetected() {
        let report = detector(fileSystem: FakeFileSystem(existing: ["/var/jb"])).run()
        #expect(report.isLikelyJailbroken)
        #expect(report.checks.first { $0.id == "files" }?.status == .failed)
    }

    @Test func multipleIndicatorsRaiseRiskToHigh() {
        let report = detector(
            fileSystem: FakeFileSystem(existing: ["/Applications/Sileo.app"], symlinks: ["/Applications"], writable: true),
            images: ["/usr/lib/TweakInject/libhooker.dylib"],
            env: ["DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"]
        ).run()
        #expect(report.risk == .high)
        #expect(report.checks.filter { $0.status == .failed }.count == 5)
    }

    @Test func simulatorDowngradesFailuresToWarnings() {
        let report = detector(fileSystem: FakeFileSystem(existing: ["/bin/bash"]), isSimulator: true).run()
        #expect(report.checks.first?.id == "simulator")
        #expect(!report.checks.contains { $0.status == .failed })
        #expect(report.risk == .low)
    }
}

@Suite("Anti-tamper")
struct AntiTamperTests {
    @Test func fridaLibrariesAreDetected() {
        let detector = InjectionDetector(
            loadedImages: { ["/usr/lib/libSystem.B.dylib", "/private/var/tmp/FridaGadget.dylib"] },
            isPortOpen: { _ in false }
        )
        let checks = detector.run()
        #expect(checks.first { $0.id == "injection-dylibs" }?.status == .failed)
        #expect(checks.first { $0.id == "frida-port" }?.status == .passed)
    }

    @Test func cleanProcessPasses() {
        let detector = InjectionDetector(loadedImages: { ["/usr/lib/libSystem.B.dylib"] }, isPortOpen: { _ in false })
        #expect(detector.run().allSatisfy { $0.status == .passed })
    }

    @Test func closedLocalPortIsReportedClosed() {
        // Port 1 (tcpmux) is essentially never listening.
        #expect(!InjectionDetector.isLocalPortOpen(1))
    }

    @Test func debuggerCheckReturnsAResult() {
        // Under `xcodebuild test` a debugger may or may not be attached; only verify the call is safe.
        _ = DebuggerDetector.isDebuggerAttached()
    }

    @Test func riskLevelFromChecks() {
        let failed = SecurityCheck(id: "a", name: "", detail: "", status: .failed)
        let passed = SecurityCheck(id: "b", name: "", detail: "", status: .passed)
        #expect(RiskLevel(checks: [passed]) == .low)
        #expect(RiskLevel(checks: [failed, passed]) == .medium)
        #expect(RiskLevel(checks: [failed, failed]) == .high)
    }
}
