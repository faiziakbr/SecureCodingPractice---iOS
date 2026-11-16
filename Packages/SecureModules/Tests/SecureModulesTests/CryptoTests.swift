import CryptoKit
import Foundation
import Testing
@testable import CryptoModule

@Suite("CryptoKit helpers")
struct CryptoTests {
    let cipher = AESGCMCipher(key: SymmetricKey(size: .bits256))

    @Test func aesGCMRoundTrip() throws {
        let message = Data("Top secret".utf8)
        let sealed = try cipher.encrypt(message)
        #expect(sealed.count == 12 + message.count + 16)
        #expect(try cipher.decrypt(sealed) == message)
    }

    @Test func aesGCMUsesFreshNonces() throws {
        let message = Data("same input".utf8)
        #expect(try cipher.encrypt(message) != cipher.encrypt(message))
    }

    @Test func aesGCMDetectsTampering() throws {
        var sealed = try cipher.encrypt(Data("Top secret".utf8))
        sealed[sealed.count - 1] ^= 0xFF
        #expect(throws: AESGCMCipher.CipherError.self) { try cipher.decrypt(sealed) }
    }

    @Test func aesGCMBindsAssociatedData() throws {
        let sealed = try cipher.encrypt(Data("payload".utf8), associatedData: Data("user-1".utf8))
        #expect(throws: AESGCMCipher.CipherError.self) {
            try cipher.decrypt(sealed, associatedData: Data("user-2".utf8))
        }
        #expect(try cipher.decrypt(sealed, associatedData: Data("user-1".utf8)) == Data("payload".utf8))
    }

    @Test func wrongKeyFails() throws {
        let sealed = try cipher.encrypt(Data("x".utf8))
        let other = AESGCMCipher(key: SymmetricKey(size: .bits256))
        #expect(throws: AESGCMCipher.CipherError.self) { try other.decrypt(sealed) }
    }

    @Test func sha256KnownVector() {
        #expect(Hashing.sha256Hex(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func hmacVerifies() {
        let key = SymmetricKey(size: .bits256)
        let message = Data("amount=100".utf8)
        let tag = Hashing.hmacSHA256(message, key: key)
        #expect(Hashing.verifyHMAC(tag, for: message, key: key))
        #expect(!Hashing.verifyHMAC(tag, for: Data("amount=900".utf8), key: key))
    }

    @Test func hkdfDerivesDistinctKeysPerPurpose() {
        let master = SymmetricKey(size: .bits256)
        let salt = Data("salt".utf8)
        let a = Hashing.deriveKey(from: master, salt: salt, info: "encryption").withUnsafeBytes { Data($0) }
        let b = Hashing.deriveKey(from: master, salt: salt, info: "signing").withUnsafeBytes { Data($0) }
        #expect(a != b)
        #expect(a.count == 32)
    }
}
