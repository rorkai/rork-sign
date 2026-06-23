import Logging

/// Installs the CLI's SwiftLog backend once per process.
///
/// The library deliberately never calls `LoggingSystem.bootstrap`; command-line
/// tools own that process-wide decision. The compatibility CLI keeps the
/// handler intentionally plain so verbose output remains close to ZSign's
/// human-readable text.
enum RorkSignCLILogging {
    /// Registers the stdout log handler if no caller has done so yet.
    static func bootstrapIfNeeded() {
        _ = bootstrapOnce
    }

    private static let bootstrapOnce: Void = {
        LoggingSystem.bootstrap { _ in
            RorkSignCLIPrintLogHandler()
        }
    }()
}

/// Minimal SwiftLog handler that prints only the rendered message to stdout.
struct RorkSignCLIPrintLogHandler: LogHandler {
    /// Metadata attached to log records created through this handler.
    var metadata: Logger.Metadata = [:]

    /// Optional provider for task-local or process-wide metadata.
    var metadataProvider: Logger.MetadataProvider?

    /// Minimum level emitted by this handler.
    var logLevel: Logger.Level = .info

    /// Reads and writes per-key metadata values.
    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get {
            metadata[key]
        }
        set {
            metadata[key] = newValue
        }
    }

    /// Emits one already-formatted signing diagnostic line.
    func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        print(message.description)
    }

    #if compiler(>=6.2)
    /// Emits one structured event through the newer SwiftLog handler contract.
    func log(event: LogEvent) {
        print(event.message.description)
    }
    #endif
}
