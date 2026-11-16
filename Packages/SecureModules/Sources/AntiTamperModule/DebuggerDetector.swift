import Darwin
import Foundation
import SecurityCore

/// Detects (and optionally blocks) debuggers attached to the process.
public enum DebuggerDetector {
    /// `true` when a debugger (LLDB, or a tracer like Frida in some modes) is attached.
    ///
    /// Asks the kernel for this process's `kinfo_proc` and checks the `P_TRACED` flag.
    public static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Calls `ptrace(PT_DENY_ATTACH)`: future debugger attach attempts fail, and if a debugger is
    /// **already** attached the process exits immediately.
    ///
    /// `ptrace` isn't exposed to Swift on iOS, so it's resolved at runtime with `dlsym`.
    /// Call this early (e.g. in `App.init`) in **Release** builds only — it breaks Xcode debugging.
    /// It is a speed bump, not a wall: it can be patched out of the binary or hooked.
    @discardableResult
    public static func denyDebuggerAttachment() -> Bool {
        typealias PtraceFunction = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptDenyAttach: CInt = 31
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
        guard let symbol = dlsym(rtldDefault, "ptrace") else { return false }
        let ptrace = unsafeBitCast(symbol, to: PtraceFunction.self)
        return ptrace(ptDenyAttach, 0, 0, 0) == 0
    }

    public static func check() -> SecurityCheck {
        let attached = isDebuggerAttached()
        return SecurityCheck(
            id: "debugger",
            name: "Debugger attached",
            detail: attached
                ? (RuntimeEnvironment.isDebugBuild ? "P_TRACED is set — expected when running from Xcode." : "P_TRACED is set on a release build!")
                : "P_TRACED flag is not set.",
            status: attached ? (RuntimeEnvironment.isDebugBuild ? .warning : .failed) : .passed
        )
    }
}
