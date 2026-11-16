// swift-tools-version: 6.2
//
// SecureModules — a collection of small, focused modules that each demonstrate
// one secure-coding technique on iOS. Every module ships:
//   • a reusable, testable service API (no UI dependencies in the logic), and
//   • a SwiftUI demo screen that explains and exercises it.
//
// The app links the single umbrella product `SecureModules` and imports the
// individual modules it needs (`import KeychainModule`, `import PinningModule`, ...).

import PackageDescription

let modules: [String] = [
    "KeychainModule",
    "BiometricsModule",
    "PinningModule",
    "JailbreakModule",
    "AntiTamperModule",
    "CryptoModule",
    "PrivacyModule",
    "SecureInputModule",
]

let package = Package(
    name: "SecureModules",
    platforms: [.iOS("17.6")],
    products: [
        .library(name: "SecureModules", targets: ["SecurityCore", "SecurityUI"] + modules),
    ],
    targets: [
        // Shared model types and low-level helpers (no UI).
        .target(name: "SecurityCore"),
        // Shared SwiftUI building blocks used by every demo screen.
        .target(name: "SecurityUI", dependencies: ["SecurityCore"]),

        .target(name: "KeychainModule", dependencies: ["SecurityUI"]),
        .target(name: "BiometricsModule", dependencies: ["KeychainModule", "SecurityUI"]),
        .target(name: "PinningModule", dependencies: ["SecurityUI"]),
        .target(name: "JailbreakModule", dependencies: ["SecurityCore", "SecurityUI"]),
        .target(name: "AntiTamperModule", dependencies: ["SecurityCore", "SecurityUI"]),
        .target(name: "CryptoModule", dependencies: ["KeychainModule", "SecurityUI"]),
        .target(name: "PrivacyModule", dependencies: ["SecurityUI"]),
        .target(name: "SecureInputModule", dependencies: ["KeychainModule", "SecurityUI"]),

        .testTarget(
            name: "SecureModulesTests",
            dependencies: ["SecurityCore"] + modules.map { .byName(name: $0) }
        ),
    ]
)
