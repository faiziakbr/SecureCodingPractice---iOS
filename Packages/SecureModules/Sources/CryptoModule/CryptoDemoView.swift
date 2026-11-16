import CryptoKit
import KeychainModule
import SecurityUI
import SwiftUI

/// Demo: CryptoKit — AES-GCM encryption, Secure Enclave signing, hashing and HMAC.
public struct CryptoDemoView: View {
    @State private var plaintext = "Account number: 1234-5678"
    @State private var ciphertext: Data?
    @State private var decrypted: String?
    @State private var signature: Data?
    @State private var log: [ConsoleEntry] = []

    private let store = KeychainStore(service: "com.securecodingpractice.crypto-demo")
    private static let aesKeyAccount = "aes-gcm-key"
    private static let signingKeyAccount = "secure-enclave-signing-key"

    public init() {}

    public var body: some View {
        List {
            Section {
                ModuleHeader(
                    title: "CryptoKit Encryption",
                    systemImage: "lock.doc.fill",
                    summary: "Use Apple's CryptoKit for modern, misuse-resistant crypto. Keys are generated per install and kept in the Keychain or Secure Enclave."
                )
            }

            Section("Plaintext") {
                TextField("Text to protect", text: $plaintext, axis: .vertical)
            }

            Section {
                Button("Encrypt", systemImage: "lock.fill", action: encrypt)
                    .disabled(plaintext.isEmpty)
                if let ciphertext {
                    StatusRow("Sealed box (base64)", detail: ciphertext.base64EncodedString(), status: .info)
                    Button("Decrypt", systemImage: "lock.open.fill", action: decrypt)
                    Button("Tamper with one byte, then decrypt", systemImage: "hammer.fill", role: .destructive, action: tamperAndDecrypt)
                }
                if let decrypted {
                    StatusRow("Decrypted", detail: decrypted, status: .passed)
                }
            } header: {
                Text("AES-256-GCM")
            } footer: {
                Text("Layout: 12-byte random nonce ‖ ciphertext ‖ 16-byte authentication tag. The key is stored in the Keychain.")
            }

            Section {
                if SecureEnclaveSigner.isAvailable {
                    Button("Sign with Secure Enclave key", systemImage: "signature", action: sign)
                    if signature != nil {
                        Button("Verify signature", systemImage: "checkmark.seal", action: verify)
                        Button("Verify against modified text", systemImage: "xmark.seal", action: verifyModified)
                    }
                    Button("Delete signing key", systemImage: "trash", role: .destructive, action: deleteSigningKey)
                } else {
                    StatusRow("Secure Enclave unavailable", detail: "Run on a physical device (or a simulator on Apple silicon) to try this.", status: .warning)
                }
            } header: {
                Text("Secure Enclave P-256 signing")
            } footer: {
                Text("The private key is generated inside the Secure Enclave and can never be exported.")
            }

            Section("Hashing & HMAC") {
                StatusRow("SHA-256", detail: Hashing.sha256Hex(Data(plaintext.utf8)), status: .info)
                Button("Compute HMAC-SHA256", systemImage: "number", action: computeHMAC)
            }

            Section("Output") {
                OutputConsole(entries: log)
            }

            Section("Rules of thumb") {
                InfoCard(
                    "Don't roll your own crypto",
                    message: "Avoid CommonCrypto ECB/CBC without MAC, MD5/SHA-1, hard-coded IVs or keys. AES-GCM or ChaChaPoly from CryptoKit handle nonces and integrity for you.",
                    status: .warning
                )
                InfoCard(
                    "Passwords need a slow KDF",
                    message: "SHA-256 is fast — great for integrity, terrible for password storage. Hash passwords server-side with Argon2/scrypt/bcrypt; on device, prefer not storing them at all.",
                    status: .info
                )
                CodeComparison(
                    insecure: """
                    let key = "MySuperSecretKey".data(using: .utf8)! // in the binary
                    let iv = Data(repeating: 0, count: 16)          // static IV
                    """,
                    secure: """
                    let key = try AESGCMCipher.loadOrCreateKey(in: store, account: "k")
                    let sealed = try AESGCMCipher(key: key).encrypt(data) // random nonce
                    """
                )
            }
        }
        .navigationTitle("CryptoKit")
    }

    // MARK: AES-GCM

    private func cipher() throws -> AESGCMCipher {
        AESGCMCipher(key: try AESGCMCipher.loadOrCreateKey(in: store, account: Self.aesKeyAccount))
    }

    private func encrypt() {
        do {
            ciphertext = try cipher().encrypt(Data(plaintext.utf8))
            decrypted = nil
            log.log("Encrypted \(plaintext.utf8.count) bytes", "Sealed box is \(ciphertext?.count ?? 0) bytes (12 nonce + data + 16 tag)", .passed)
        } catch {
            log.log(error: error, title: "Encryption failed")
        }
    }

    private func decrypt() {
        guard let ciphertext else { return }
        do {
            decrypted = String(decoding: try cipher().decrypt(ciphertext), as: UTF8.self)
            log.log("Decrypted successfully", "Tag verified — data is authentic", .passed)
        } catch {
            decrypted = nil
            log.log(error: error, title: "Decryption failed")
        }
    }

    private func tamperAndDecrypt() {
        guard var tampered = ciphertext, tampered.count > 13 else { return }
        tampered[12] ^= 0x01 // flip one bit in the first ciphertext byte
        do {
            _ = try cipher().decrypt(tampered)
            log.log("Tampered data decrypted?!", "This should never happen", .failed)
        } catch {
            decrypted = nil
            log.log("Tampering detected", error.localizedDescription, .passed)
        }
    }

    // MARK: Secure Enclave

    private var message: Data { Data(plaintext.utf8) }

    private func sign() {
        do {
            let signer = try SecureEnclaveSigner.loadOrCreate(in: store, account: Self.signingKeyAccount)
            signature = try signer.sign(message)
            let publicKey = signer.publicKey.derRepresentation.base64EncodedString()
            log.log("Signed with Secure Enclave key", "Public key (send to server): \(publicKey.prefix(40))…", .passed)
        } catch {
            log.log(error: error, title: "Signing failed")
        }
    }

    private func verify() {
        verify(message: message, label: "original text")
    }

    private func verifyModified() {
        verify(message: Data((plaintext + "!").utf8), label: "modified text")
    }

    private func verify(message: Data, label: String) {
        guard let signature else { return }
        do {
            let signer = try SecureEnclaveSigner.loadOrCreate(in: store, account: Self.signingKeyAccount)
            let valid = SecureEnclaveSigner.verify(signature: signature, for: message, publicKey: signer.publicKey)
            log.log(valid ? "Signature valid for \(label)" : "Signature INVALID for \(label)", "", valid ? .passed : .failed)
        } catch {
            log.log(error: error, title: "Verification failed")
        }
    }

    private func deleteSigningKey() {
        try? SecureEnclaveSigner.delete(in: store, account: Self.signingKeyAccount)
        signature = nil
        log.log("Signing key deleted", "A new key will be generated on next sign")
    }

    // MARK: HMAC

    private func computeHMAC() {
        do {
            let master = try AESGCMCipher.loadOrCreateKey(in: store, account: Self.aesKeyAccount)
            // Derive a separate key for MACs instead of reusing the encryption key.
            let macKey = Hashing.deriveKey(from: master, salt: Data("demo-salt".utf8), info: "hmac")
            let tag = Hashing.hmacSHA256(message, key: macKey)
            let valid = Hashing.verifyHMAC(tag, for: message, key: macKey)
            log.log("HMAC-SHA256 (HKDF-derived key)", "\(tag.hexString)\nVerified in constant time: \(valid)", .passed)
        } catch {
            log.log(error: error, title: "HMAC failed")
        }
    }
}

#Preview {
    NavigationStack { CryptoDemoView() }
}
