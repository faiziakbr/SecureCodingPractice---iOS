import Testing
@testable import SecureInputModule

@Suite("InputValidator")
struct InputValidatorTests {
    @Test func normalizationStripsControlAndZeroWidthCharacters() {
        #expect(InputValidator.normalize("  al\u{200B}ice\u{0007}\n") == "alice")
        #expect(InputValidator.normalize("e\u{0301}") == "\u{00E9}") // NFC composition
    }

    @Test(arguments: ["alice", "bob_99", "j.doe"])
    func validUsernames(_ name: String) {
        #expect(InputValidator.validateUsername(name).isValid)
    }

    @Test(arguments: ["ab", "robert'); DROP TABLE users;--", "<script>", ".hidden", String(repeating: "a", count: 21)])
    func invalidUsernames(_ name: String) {
        #expect(!InputValidator.validateUsername(name).isValid)
    }

    @Test func emailIsLowercasedAndValidated() {
        let result = InputValidator.validateEmail("  Alice@Example.COM ")
        #expect(result.isValid)
        #expect(result.sanitized == "alice@example.com")
        #expect(!InputValidator.validateEmail("not-an-email").isValid)
        #expect(!InputValidator.validateEmail("a@b").isValid)
    }

    @Test func pinRejectsTrivialPatterns() {
        #expect(InputValidator.validatePIN("2580").isValid)
        #expect(InputValidator.validatePIN("1111").isValid == false)
        #expect(InputValidator.validatePIN("1234").isValid == false)
        #expect(InputValidator.validatePIN("4321").isValid == false)
        #expect(InputValidator.validatePIN("12a4").isValid == false)
        #expect(InputValidator.validatePIN("8264").isValid)
    }

    @Test func passwordRules() {
        #expect(InputValidator.validatePassword("Correct-Horse-9-Battery").isValid)
        #expect(!InputValidator.validatePassword("short1!A").isValid)
        #expect(!InputValidator.validatePassword("alllowercase-1234").isValid)
        #expect(!InputValidator.validatePassword("Alice-Secret-2026", username: "alice").isValid)
    }

    @Test func urlAllowList() {
        let hosts: Set<String> = ["example.com"]
        #expect(InputValidator.validateURL("https://example.com/path", allowedHosts: hosts).isValid)
        #expect(!InputValidator.validateURL("http://example.com/path", allowedHosts: hosts).isValid)
        #expect(!InputValidator.validateURL("https://evil.com/path", allowedHosts: hosts).isValid)
        #expect(!InputValidator.validateURL("https://user:pw@example.com", allowedHosts: hosts).isValid)
        #expect(!InputValidator.validateURL("javascript:alert(1)", allowedHosts: hosts).isValid)
    }
}
