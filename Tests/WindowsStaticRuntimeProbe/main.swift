import Dispatch

/// Exercises delayed-task entry points that ordinary help commands never reach.
@main
struct WindowsStaticRuntimeProbe {
    static func main() async throws {
        try await Task.sleep(for: .milliseconds(25))
        try await Task.sleep(nanoseconds: 25_000_000)

        let clock = ContinuousClock()
        try await clock.sleep(
            until: clock.now.advanced(by: .milliseconds(25))
        )

        print("Static delayed-task runtime probe passed.")
    }
}
