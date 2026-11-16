import Foundation
import MachO

/// Helpers for inspecting the dynamic libraries loaded into the current process.
/// Used by jailbreak detection (tweak injection frameworks) and anti-tamper (Frida, cycript).
public enum LoadedImages {
    /// Paths of every image (executable + dylibs + frameworks) currently loaded by dyld.
    public static func current() -> [String] {
        let count = _dyld_image_count()
        var names: [String] = []
        names.reserveCapacity(Int(count))
        for index in 0..<count {
            if let cName = _dyld_get_image_name(index) {
                names.append(String(cString: cName))
            }
        }
        return names
    }

    /// Returns the loaded images whose path contains any of `needles` (case-insensitive).
    public static func matching(_ needles: [String], in images: [String]) -> [String] {
        let lowered = needles.map { $0.lowercased() }
        return images.filter { path in
            let lowerPath = path.lowercased()
            return lowered.contains { lowerPath.contains($0) }
        }
    }
}
