import SwiftUI
import UIKit

// MARK: - App-switcher snapshot protection

/// Covers the content whenever the scene is not active.
///
/// iOS takes a snapshot of your UI when the app moves to the background and shows it in the app
/// switcher (and stores it on disk). Without a cover, account balances, messages or one-time codes
/// leak into that snapshot.
struct PrivacyProtectedModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active {
                PrivacyCover(message: "Content hidden while the app is in the background")
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: scenePhase)
    }
}

// MARK: - Screen recording / mirroring protection

/// Hides the content while the screen is being recorded, mirrored or AirPlayed.
struct ScreenCaptureProtectedModifier: ViewModifier {
    @State private var isCaptured = false

    func body(content: Content) -> some View {
        content
            .overlay {
                if isCaptured {
                    PrivacyCover(message: "Hidden during screen recording")
                }
            }
            .onAppear(perform: refresh)
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
                refresh()
            }
    }

    private func refresh() {
        isCaptured = ScreenCaptureState.isCaptured
    }
}

/// Reads the capture state from the active window scene (`UIScreen.isCaptured` is deprecated).
public enum ScreenCaptureState {
    @MainActor
    public static var isCaptured: Bool {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { $0.traitCollection.sceneCaptureState == .active }
    }
}

struct PrivacyCover: View {
    let message: String

    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThickMaterial)
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.tint)
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
        .ignoresSafeArea()
    }
}

public extension View {
    /// Covers the view in the app switcher / when the app is inactive. Apply once at the root.
    func privacyProtected() -> some View {
        modifier(PrivacyProtectedModifier())
    }

    /// Hides the view while the screen is recorded or mirrored.
    func screenCaptureProtected() -> some View {
        modifier(ScreenCaptureProtectedModifier())
    }
}
