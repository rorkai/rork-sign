import Logging

/// Severity for signing diagnostic events.
public enum SigningDiagnosticLevel: Equatable, Sendable {
    /// High-level signing progress and preflight metadata.
    case info

    /// Detailed path-level events such as sealed bundles and cache hits.
    case debug
}

/// Optional structured logging sink used by signing flows.
///
/// Library calls are silent by default. Supplying a SwiftLog `Logger` lets CLI
/// tools, apps, or build systems decide where signing diagnostics should go and
/// which levels should be emitted without making the core signer print directly.
public struct SigningDiagnostics {
    /// Disabled diagnostics for callers that do not want signing logs.
    public static var disabled: SigningDiagnostics {
        SigningDiagnostics()
    }

    /// Logger used for signing diagnostics when logging is enabled.
    public var logger: Logger?

    /// Optional event handler for integrations that cannot traffic in SwiftLog
    /// values directly, such as Objective-C facades.
    public var eventHandler: ((SigningDiagnosticLevel, String) -> Void)?

    /// Creates diagnostics backed by an optional SwiftLog logger.
    ///
    /// Pass no logger or event handler to keep signing silent. The caller
    /// remains responsible for bootstrapping `LoggingSystem` in command-line
    /// tools or applications.
    public init(
        logger: Logger? = nil,
        eventHandler: ((SigningDiagnosticLevel, String) -> Void)? = nil
    ) {
        self.logger = logger
        self.eventHandler = eventHandler
    }

    /// Emits a high-level signing message.
    func info(_ message: Logger.Message, metadata: Logger.Metadata = [:]) {
        logger?.info(message, metadata: metadata)
        eventHandler?(.info, message.description)
    }

    /// Emits a diagnostic detail useful while inspecting signing behavior.
    func debug(_ message: Logger.Message, metadata: Logger.Metadata = [:]) {
        logger?.debug(message, metadata: metadata)
        eventHandler?(.debug, message.description)
    }
}
