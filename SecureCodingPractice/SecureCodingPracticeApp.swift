//
//  SecureCodingPracticeApp.swift
//  SecureCodingPractice
//
//  Created by Faizan on 16/11/2026.
//

import AntiTamperModule
import PrivacyModule
import SwiftUI

@main
struct SecureCodingPracticeApp: App {
    init() {
        #if !DEBUG
        // Block debuggers from attaching in release builds (see AntiTamperModule).
        DebuggerDetector.denyDebuggerAttachment()
        #endif
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                // Cover the UI in the app switcher so sensitive data isn't captured in the snapshot.
                .privacyProtected()
        }
    }
}
