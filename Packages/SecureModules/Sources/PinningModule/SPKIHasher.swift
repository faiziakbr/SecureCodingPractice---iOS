import CryptoKit
import Foundation
import Security

/// Computes the base64 SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
///
/// This is the same value you get from:
/// ```
/// openssl x509 -in cert.pem -pubkey -noout \
///   | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | base64
/// ```
/// Pinning the public key (SPKI) instead of the whole certificate means the pin survives
/// certificate renewals as long as the key pair is reused.
public enum SPKIHasher {
    public static func sha256Base64(for certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate) else { return nil }
        return sha256Base64(for: key)
    }

    public static func sha256Base64(for publicKey: SecKey) -> String? {
        guard
            let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
            let keyType = attributes[kSecAttrKeyType as String] as? String,
            let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int,
            let header = asn1Header(keyType: keyType, keySize: keySize),
            let rawKey = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else { return nil }

        // SecKeyCopyExternalRepresentation returns the bare key (PKCS#1 for RSA, X9.63 for EC).
        // Prefixing the algorithm-specific ASN.1 header reconstructs the DER SubjectPublicKeyInfo.
        let spki = Data(header) + rawKey
        return Data(SHA256.hash(data: spki)).base64EncodedString()
    }

    /// DER prefixes for SubjectPublicKeyInfo of common key types.
    static func asn1Header(keyType: String, keySize: Int) -> [UInt8]? {
        let rsa = kSecAttrKeyTypeRSA as String
        let ec = kSecAttrKeyTypeECSECPrimeRandom as String
        let header: [UInt8]? = switch (keyType, keySize) {
        case (rsa, 2048):
            [0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
             0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00]
        case (rsa, 3072):
            [0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
             0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00]
        case (rsa, 4096):
            [0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
             0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00]
        case (ec, 256):
            [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
             0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
        case (ec, 384):
            [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
             0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
        case (ec, 521):
            [0x30, 0x81, 0x9B, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05,
             0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00]
        default:
            nil
        }
        return header
    }
}
