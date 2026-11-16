//
//  ModuleCatalog.swift
//  SecureCodingPractice
//

import AntiTamperModule
import BiometricsModule
import CryptoModule
import JailbreakModule
import KeychainModule
import PinningModule
import PrivacyModule
import SecureInputModule
import SwiftUI

/// Every secure-coding module shown on the home screen.
enum SecureModule: String, CaseIterable, Identifiable, Hashable {
    case keychain
    case biometrics
    case pinning
    case jailbreak
    case antiTamper
    case crypto
    case privacy
    case secureInput

    var id: String { rawValue }

    var title: String {
        switch self {
        case .keychain: "Keychain Storage"
        case .biometrics: "Face ID / Touch ID"
        case .pinning: "SSL / CA Pinning"
        case .jailbreak: "Jailbreak Detection"
        case .antiTamper: "Anti-Debug & Tamper"
        case .crypto: "CryptoKit Encryption"
        case .privacy: "Screen & Data Privacy"
        case .secureInput: "Secure Input & Storage"
        }
    }

    var subtitle: String {
        switch self {
        case .keychain: "Save, read and delete secrets with the right accessibility class"
        case .biometrics: "LocalAuthentication and biometry-bound Keychain items"
        case .pinning: "Public-key pinning with URLSession and SecTrust"
        case .jailbreak: "Layered heuristics for rooted / jailbroken devices"
        case .antiTamper: "Debugger, Frida injection and repackaging checks"
        case .crypto: "AES-GCM, Secure Enclave signing, hashing and HMAC"
        case .privacy: "App-switcher cover, screen recording, clipboard, file protection"
        case .secureInput: "Validation, private logging, UserDefaults vs Keychain"
        }
    }

    var systemImage: String {
        switch self {
        case .keychain: "key.fill"
        case .biometrics: "faceid"
        case .pinning: "pin.fill"
        case .jailbreak: "lock.trianglebadge.exclamationmark.fill"
        case .antiTamper: "ant.fill"
        case .crypto: "lock.doc.fill"
        case .privacy: "eye.slash.fill"
        case .secureInput: "text.badge.checkmark"
        }
    }

    var tint: Color {
        switch self {
        case .keychain: .orange
        case .biometrics: .green
        case .pinning: .blue
        case .jailbreak: .red
        case .antiTamper: .purple
        case .crypto: .indigo
        case .privacy: .teal
        case .secureInput: .pink
        }
    }

    @ViewBuilder
    var destination: some View {
        switch self {
        case .keychain: KeychainDemoView()
        case .biometrics: BiometricsDemoView()
        case .pinning: PinningDemoView()
        case .jailbreak: JailbreakDemoView()
        case .antiTamper: AntiTamperDemoView(expectedBundleIdentifier: "com.faizan.SecureCodingPractice")
        case .crypto: CryptoDemoView()
        case .privacy: PrivacyDemoView()
        case .secureInput: SecureInputDemoView()
        }
    }
}
