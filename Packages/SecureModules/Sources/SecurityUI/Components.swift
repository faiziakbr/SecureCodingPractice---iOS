@_exported import SecurityCore
import SwiftUI

// MARK: - Status styling

public extension CheckStatus {
    var systemImage: String {
        switch self {
        case .passed: "checkmark.shield.fill"
        case .failed: "xmark.octagon.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .info: "info.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .passed: .green
        case .failed: .red
        case .warning: .orange
        case .info: .blue
        }
    }
}

public extension RiskLevel {
    var color: Color {
        switch self {
        case .low: .green
        case .medium: .orange
        case .high: .red
        }
    }
}

// MARK: - Module header

/// Large header shown at the top of every demo screen.
public struct ModuleHeader: View {
    let title: String
    let systemImage: String
    let summary: String

    public init(title: String, systemImage: String, summary: String) {
        self.title = title
        self.systemImage = systemImage
        self.summary = summary
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: systemImage)
                .font(.system(size: 30, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(summary).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 6)
    }
}

// MARK: - Info card

/// A short explanation block. Use `.warning` for caveats and `.info` for background.
public struct InfoCard: View {
    let title: String
    let message: String
    let status: CheckStatus

    public init(_ title: String, message: String, status: CheckStatus = .info) {
        self.title = title
        self.message = message
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: status.systemImage)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(status.color)
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Status row

/// One row in a list of security checks.
public struct StatusRow: View {
    let title: String
    let detail: String
    let status: CheckStatus

    public init(_ title: String, detail: String, status: CheckStatus) {
        self.title = title
        self.detail = detail
        self.status = status
    }

    public init(check: SecurityCheck) {
        self.init(check.name, detail: check.detail, status: check.status)
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: status.systemImage)
                .foregroundStyle(status.color)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Code comparison

/// Shows an insecure snippet next to its secure counterpart.
public struct CodeComparison: View {
    let insecure: String
    let secure: String

    public init(insecure: String, secure: String) {
        self.insecure = insecure
        self.secure = secure
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            CodeBlock(label: "Don't", code: insecure, status: .failed)
            CodeBlock(label: "Do", code: secure, status: .passed)
        }
        .padding(.vertical, 4)
    }
}

/// A monospaced, horizontally scrollable code snippet.
public struct CodeBlock: View {
    let label: String
    let code: String
    let status: CheckStatus

    public init(label: String, code: String, status: CheckStatus = .info) {
        self.label = label
        self.code = code
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(label, systemImage: status.systemImage)
                .font(.caption.weight(.semibold))
                .foregroundStyle(status.color)
            ScrollView(.horizontal, showsIndicators: false) {
                Text(code)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(10)
            }
            .background(status.color.opacity(0.08), in: .rect(cornerRadius: 8))
        }
    }
}

// MARK: - Output console

/// Running log of what a demo did, newest first.
public struct OutputConsole: View {
    let entries: [ConsoleEntry]

    public init(entries: [ConsoleEntry]) {
        self.entries = entries
    }

    public var body: some View {
        if entries.isEmpty {
            Text("No output yet — try one of the actions above.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            ForEach(entries) { entry in
                StatusRow(entry.title, detail: entry.detail, status: entry.status)
            }
        }
    }
}

public struct ConsoleEntry: Identifiable, Sendable {
    public let id = UUID()
    public let title: String
    public let detail: String
    public let status: CheckStatus

    public init(_ title: String, detail: String = "", status: CheckStatus = .info) {
        self.title = title
        self.detail = detail
        self.status = status
    }
}

public extension Array where Element == ConsoleEntry {
    /// Inserts at the top and keeps the log bounded.
    mutating func log(_ title: String, _ detail: String = "", _ status: CheckStatus = .info) {
        insert(ConsoleEntry(title, detail: detail, status: status), at: 0)
        if count > 30 { removeLast(count - 30) }
    }

    mutating func log(error: Error, title: String) {
        log(title, error.localizedDescription, .failed)
    }
}

// MARK: - Risk badge

public struct RiskBadge: View {
    let level: RiskLevel

    public init(_ level: RiskLevel) {
        self.level = level
    }

    public var body: some View {
        Text("\(level.rawValue) risk")
            .font(.caption.weight(.bold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .foregroundStyle(.white)
            .background(level.color, in: .capsule)
    }
}
