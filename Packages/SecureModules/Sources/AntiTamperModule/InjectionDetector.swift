import Darwin
import Foundation
import SecurityCore

/// Detects dynamic instrumentation toolkits (Frida, cycript) commonly used to hook app logic at runtime.
public struct InjectionDetector: Sendable {
    public static let suspiciousLibraries = ["FridaGadget", "frida-agent", "frida", "libcycript", "cynject", "libinjector"]
    /// Default `frida-server` listening ports.
    public static let fridaPorts: [UInt16] = [27042, 27043]

    private let loadedImages: @Sendable () -> [String]
    private let isPortOpen: @Sendable (UInt16) -> Bool

    public init(
        loadedImages: @escaping @Sendable () -> [String] = LoadedImages.current,
        isPortOpen: @escaping @Sendable (UInt16) -> Bool = InjectionDetector.isLocalPortOpen
    ) {
        self.loadedImages = loadedImages
        self.isPortOpen = isPortOpen
    }

    public func run() -> [SecurityCheck] {
        [libraryCheck(), fridaServerCheck()]
    }

    func libraryCheck() -> SecurityCheck {
        let matches = LoadedImages.matching(Self.suspiciousLibraries, in: loadedImages())
            .map { ($0 as NSString).lastPathComponent }
        return SecurityCheck(
            id: "injection-dylibs",
            name: "Instrumentation libraries",
            detail: matches.isEmpty ? "No Frida/cycript libraries in the process." : "Loaded: \(matches.joined(separator: ", "))",
            status: matches.isEmpty ? .passed : .failed
        )
    }

    func fridaServerCheck() -> SecurityCheck {
        let open = Self.fridaPorts.filter(isPortOpen)
        return SecurityCheck(
            id: "frida-port",
            name: "frida-server port",
            detail: open.isEmpty
                ? "Nothing listening on localhost:\(Self.fridaPorts.map(String.init).joined(separator: "/"))."
                : "Something is listening on localhost:\(open.map(String.init).joined(separator: ", "))\(RuntimeEnvironment.isSimulator ? " (on the host Mac)" : "").",
            status: open.isEmpty ? .passed : (RuntimeEnvironment.isSimulator ? .warning : .failed)
        )
    }

    /// Tries a TCP connect to 127.0.0.1:`port`. A refused connection returns immediately.
    public static func isLocalPortOpen(_ port: UInt16) -> Bool {
        let socketFD = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else { return false }
        defer { close(socketFD) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}
