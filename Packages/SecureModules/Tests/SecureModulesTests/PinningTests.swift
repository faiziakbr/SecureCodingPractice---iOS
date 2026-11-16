import Foundation
import Security
import Testing
@testable import PinningModule

@Suite("SSL pinning")
struct PinningTests {
    // Expected values computed with:
    // openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64

    /// GTS Root R4 (cross-signed by GlobalSign) — EC P-384 key.
    static let gtsRootR4DER = "MIIDejCCAmKgAwIBAgIQf+UwvzMTQ77dghYQST2KGzANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UECxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIzMTExNTAzNDMyMVoXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFI0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE83Rzp2iLYK5DuDXFgTB7S0md+8FhzubeRr1r1WEYNa5A3XP3iZEwWus87oV8okB2O6nGuEfYKueSkWpz6bFyOZ8pn6KY019eWIZlD6GEZQbR3IvJx3PIjGov5cSr0R2Ko4H/MIH8MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUgEzW63T/STaj1dj8tT7FavCUHYwwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzAChhpodHRwOi8vaS5wa2kuZ29vZy9nc3IxLmNydDAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vYy5wa2kuZ29vZy9yL2dzcjEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQAYQrsPBtYDh5bjP2OBDwmkoWhIDDkic574y04tfzHpn+cJodI2D4SseesQ6bDrarZ7C30ddLibZatoKiws3UL9xnELz4ct92vID24FfVbiI1hY+SW6FoVHkNeWIP0GCbaM4C6uVdF5dTUsMVs/ZbzNnIdCp5Gxmx5ejvEau8otR/CskGN+hr/W5GvT1tMBjgWKZ1i4//emhA1JG1BbPzoLJQvyEotc03lXjTaCzv8mEbep8RqZ7a2CPsgRbuvTPBwcOMBBmuFeU88+FSBX6+7iP0il8b4Z0QFqIwwMHfs/L6K1vepuoxtGzi4CZ68zJpiq1UvSqTbFJjtbD4seiMHl"

    /// Apple Public EV Server RSA CA 1 - G1 — RSA 2048 key.
    static let appleEVRSADER = "MIIFHjCCBAagAwIBAgIQBPIuzCH8tDgqwouPLWQfwDANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0yMDA0MjkxMjU1MzRaFw0zMDA0MTAyMzU5NTlaMFExCzAJBgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMS0wKwYDVQQDEyRBcHBsZSBQdWJsaWMgRVYgU2VydmVyIFJTQSBDQSAxIC0gRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfn5fdV0A4cCNFu0EvUgduZVPyPZity4q8Re1TcE9qGyWoVpzHm9OluDlqwcvudbLwBe25PWA2Z9xFpVKK9jGW6Vt79N7if7dfi9w2+2zG+/wJu1Z6TA8RENTVuJTaMwqQXw1dTkZEOgjCEKa75uyzXl+mIa0s4GdxkCBclGI9WDsUFlLj3A6eBIzeTomTl7LhIV+nQUEWTqkwG5Pcxckiv7Xn1mu7EVWUukZWY8uL+KhcTJQZYtxNj3PeM73WZ3fraixPA+RBkVnG5NgObRnrk5VHwjntbit9892kp7EISZK4Izfm99QgP4V2IqHFsKxfCnZqfwUHikxftIVkjXIdAgMBAAGjggHgMIIB3DAdBgNVHQ4EFgQU073BPKDPNbk0xdTb2hAOTN5q/lgwHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmwwgdwGA1UdIASB1DCB0TCBxQYJYIZIAYb9bAIBMIG3MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGKBggrBgEFBQcCAjB+DHxBbnkgdXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgUmVseWluZyBQYXJ0eSBBZ3JlZW1lbnQgbG9jYXRlZCBhdCBodHRwczovL3d3dy5kaWdpY2VydC5jb20vcnBhLXVhMAcGBWeBDAEBMA0GCSqGSIb3DQEBCwUAA4IBAQBD9c6SmtMxGjRwc/A1bPiM+r1qj5xbDzGn6s6m6oggm9UeBLCSUNJthKffNPqqwtULeeUddssewaOZX+uHjG9bY/O9J1VQtGtXI2hndyAPiloqNjf5iBW16h3ZIUFQL319hISioItFVJZnVe4gjNEWio1ZRwO5A4e/H69/lPAX294yGtYGllAdv2NexhUMfjODhCajoTJmkXbyIpYzTNkgDXvQptTecrvr0rPzEMWfTtGSppbOC+s/5jG3aJ6GJn49Ram1ZLEGHTx9PWUoHth9Lj7vwFBD9667x9m9nUhuET9a3XvNep+N7w96ZqH2fAqUBW1kl6u3u67D6mvDsCQr"

    private func certificate(_ base64: String) throws -> SecCertificate {
        let der = try #require(Data(base64Encoded: base64))
        return try #require(SecCertificateCreateWithData(nil, der as CFData))
    }

    @Test func spkiHashMatchesOpenSSLForECP384() throws {
        let hash = SPKIHasher.sha256Base64(for: try certificate(Self.gtsRootR4DER))
        #expect(hash == DemoPins.gtsRootR4)
    }

    @Test func spkiHashMatchesOpenSSLForRSA2048() throws {
        let hash = SPKIHasher.sha256Base64(for: try certificate(Self.appleEVRSADER))
        #expect(hash == "9C7mf4J789KvLX59lcMyYpsH6bpdmoAGTByZNhcusLA=")
    }

    @Test func policyMatchesHostsAndSubdomains() {
        let policy = PinningPolicy(pinnedHosts: [
            PinnedHost(host: "example.com", pins: ["a"], includesSubdomains: true),
            PinnedHost(host: "api.other.com", pins: ["b"]),
        ])
        #expect(policy.pins(for: "example.com") == ["a"])
        #expect(policy.pins(for: "API.Example.com") == ["a"])
        #expect(policy.pins(for: "api.other.com") == ["b"])
        #expect(policy.pins(for: "x.api.other.com") == nil)
        #expect(policy.pins(for: "notexample.com") == nil)
    }

    @Test func unpinnedHostHandling() throws {
        let trust = try makeTrust()
        let lenient = PinningURLSessionDelegate(policy: PinningPolicy(pinnedHosts: []))
        #expect(lenient.evaluate(trust: trust, host: "unpinned.com").outcome == .notPinned)

        let strict = PinningURLSessionDelegate(policy: PinningPolicy(pinnedHosts: [], rejectUnpinnedHosts: true))
        #expect(strict.evaluate(trust: trust, host: "unpinned.com").outcome == .rejectedUnpinned)
    }

    @Test func invalidChainFailsTrustBeforePinCheck() throws {
        // A lone intermediate presented for the wrong host must fail standard validation,
        // even though its key is in the pin set.
        let trust = try makeTrust()
        let delegate = PinningURLSessionDelegate(policy: PinningPolicy(pinnedHosts: [
            PinnedHost(host: "pinned.com", pins: [DemoPins.gtsRootR4]),
        ]))
        let outcome = delegate.evaluate(trust: trust, host: "pinned.com").outcome
        guard case .trustFailed = outcome else {
            Issue.record("Expected trustFailed, got \(outcome)")
            return
        }
    }

    private func makeTrust() throws -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(
            try certificate(Self.gtsRootR4DER),
            SecPolicyCreateSSL(true, "pinned.com" as CFString),
            &trust
        )
        #expect(status == errSecSuccess)
        return try #require(trust)
    }
}
