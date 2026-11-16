import Foundation
import Security
import os

/// A certificate seen in the server's validated chain.
public struct ChainCertificate: Sendable, Hashable, Identifiable {
    public var id: String { "\(index)-\(spkiHash)" }
    public let index: Int
    public let subject: String
    public let spkiHash: String
    public let isPinMatch: Bool
}

/// The outcome of evaluating one server-trust challenge.
public struct PinningEvaluation: Sendable {
    public enum Outcome: Sendable, Equatable {
        /// Chain is valid and contains a pinned key.
        case pinMatched
        /// Chain is valid, but none of its keys are pinned → connection cancelled.
        case pinMismatch
        /// Standard TLS validation failed (expired, wrong host, untrusted root, ...).
        case trustFailed(String)
        /// Host has no pins; default system validation was used.
        case notPinned
        /// Host has no pins and the policy rejects unpinned hosts.
        case rejectedUnpinned
    }

    public let host: String
    public let outcome: Outcome
    public let chain: [ChainCertificate]
}

/// Thread-safe sink the delegate writes evaluations into, so callers can inspect what happened.
public final class PinningEvaluationRecorder: Sendable {
    private let storage = OSAllocatedUnfairLock<[PinningEvaluation]>(initialState: [])

    public init() {}

    func record(_ evaluation: PinningEvaluation) {
        storage.withLock { $0.append(evaluation) }
    }

    public var evaluations: [PinningEvaluation] {
        storage.withLock { $0 }
    }
}

/// `URLSessionDelegate` that enforces public-key (SPKI) pinning.
///
/// Order of operations matters:
/// 1. Run normal system trust evaluation first (`SecTrustEvaluateWithError`) — pinning is an
///    *additional* check, never a replacement for chain/hostname/expiry validation.
/// 2. Walk the validated chain and hash each certificate's public key.
/// 3. Accept only if a hash is in the pin set; otherwise cancel the challenge.
public final class PinningURLSessionDelegate: NSObject, URLSessionDelegate, Sendable {
    public let policy: PinningPolicy
    public let recorder: PinningEvaluationRecorder

    public init(policy: PinningPolicy, recorder: PinningEvaluationRecorder = PinningEvaluationRecorder()) {
        self.policy = policy
        self.recorder = recorder
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard
            challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host
        let evaluation = evaluate(trust: trust, host: host)
        recorder.record(evaluation)

        switch evaluation.outcome {
        case .pinMatched:
            completionHandler(.useCredential, URLCredential(trust: trust))
        case .notPinned:
            completionHandler(.performDefaultHandling, nil)
        case .pinMismatch, .trustFailed, .rejectedUnpinned:
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Pure evaluation logic, separated from the delegate callback for clarity and testing.
    public func evaluate(trust: SecTrust, host: String) -> PinningEvaluation {
        guard let pins = policy.pins(for: host) else {
            return PinningEvaluation(
                host: host,
                outcome: policy.rejectUnpinnedHosts ? .rejectedUnpinned : .notPinned,
                chain: []
            )
        }

        // Make sure the hostname is part of validation (SSL policy with the expected host).
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))

        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError) else {
            let message = trustError.map { CFErrorCopyDescription($0) as String } ?? "Unknown trust failure"
            return PinningEvaluation(host: host, outcome: .trustFailed(message), chain: [])
        }

        let certificates = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let chain = certificates.enumerated().map { index, certificate in
            let hash = SPKIHasher.sha256Base64(for: certificate) ?? "<unsupported key type>"
            return ChainCertificate(
                index: index,
                subject: (SecCertificateCopySubjectSummary(certificate) as String?) ?? "Unknown subject",
                spkiHash: hash,
                isPinMatch: pins.contains(hash)
            )
        }

        let matched = chain.contains { $0.isPinMatch }
        return PinningEvaluation(host: host, outcome: matched ? .pinMatched : .pinMismatch, chain: chain)
    }
}

/// Convenience: a `URLSession` configured with pinning and safe defaults.
public enum PinnedSession {
    public static func make(policy: PinningPolicy, recorder: PinningEvaluationRecorder = PinningEvaluationRecorder()) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral // no disk cache/cookies for sensitive traffic
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        return URLSession(
            configuration: configuration,
            delegate: PinningURLSessionDelegate(policy: policy, recorder: recorder),
            delegateQueue: nil
        )
    }
}
