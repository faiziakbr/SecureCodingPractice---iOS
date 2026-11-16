# Secure Coding Practice (iOS)

A SwiftUI reference app where every iOS secure-coding technique lives in its own module.
Each module has a reusable, testable service API and a demo screen. The demo screen explains the technique, lets you try it, and shows "Don't / Do" code.

## Layout

```
SecureCodingPractice/            App target: home screen + module catalog
Packages/SecureModules/          Local Swift package (one target per module)
  Sources/
    SecurityCore/                Shared models (SecurityCheck, RiskLevel) + dyld image helpers
    SecurityUI/                  Shared SwiftUI components (headers, status rows, code blocks)
    KeychainModule/              KeychainStore: Data/String/Codable, accessibility classes, upsert
    BiometricsModule/            BiometricAuthenticator (LAContext) + BiometricVault (.biometryCurrentSet)
    PinningModule/               SPKI hashing, PinningPolicy, PinningURLSessionDelegate (CA/leaf pinning)
    JailbreakModule/             JailbreakDetector: files, sandbox, symlinks, injected dylibs, env
    AntiTamperModule/            Debugger (P_TRACED, PT_DENY_ATTACH), Frida detection, integrity checks
    CryptoModule/                AES-GCM, Secure Enclave P-256 signing, SHA-256, HMAC, HKDF
    PrivacyModule/               App-switcher cover, screen-recording cover, expiring pasteboard, file protection
    SecureInputModule/           Allow-list validation, os.Logger privacy, UserDefaults vs Keychain
  Tests/SecureModulesTests/      Swift Testing suites for the pure logic
```

The app links one umbrella product, `SecureModules`, and imports the modules it needs
(`import KeychainModule`, `import PinningModule`, …).

## Running

- App: open `SecureCodingPractice.xcodeproj` and run the `SecureCodingPractice` scheme on any **iOS 17.6+** simulator or device.
- Tests:
  ```sh
  cd Packages/SecureModules
  xcodebuild test -scheme SecureModules -destination 'platform=iOS Simulator,name=iPhone 17'
  ```

## Notes

- **Face ID on the Simulator:** Features ▸ Face ID ▸ Enrolled, then Matching / Non-matching Face while the prompt is up. `NSFaceIDUsageDescription` is set in the target's build settings.
- **Jailbreak / anti-tamper results on the Simulator are not meaningful.** The simulator sees the Mac's file system and runs under Xcode's debugger. Failures there are shown as warnings. Test on a real device.
- **Pinning demo** pins the Google Trust Services root CA keys for `google.com`. If Google ever moves to a different CA, refresh the pins in `PinningPolicy.swift` (`DemoPins`) with the `openssl` pipeline documented in `SPKIHasher.swift`.
- Client-side checks raise an attacker's cost but can always be bypassed. Enforce decisions on the server and use App Attest (`DCAppAttestService`) for real integrity guarantees.
