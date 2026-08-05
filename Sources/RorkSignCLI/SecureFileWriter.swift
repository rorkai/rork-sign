import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(WinSDK)
import WinSDK
#endif

/// Publishes sensitive output only after a protected sibling file is complete.
enum SecureFileWriter {
    /// Writes data through a protected temporary file and atomically replaces
    /// the destination after durable storage succeeds.
    ///
    /// - Parameters:
    ///   - data: The sensitive bytes to write.
    ///   - outputURL: The final destination.
    static func writeAtomically(_ data: Data, to outputURL: URL) throws {
        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let temporaryURL = outputURL
            .deletingLastPathComponent()
            .appendingPathComponent(
                ".\(outputURL.lastPathComponent).\(UUID().uuidString).tmp"
            )

        #if os(Windows)
        try writeOnWindows(
            data,
            temporaryURL: temporaryURL,
            outputURL: outputURL
        )
        #else
        try writeOnPOSIX(
            data,
            temporaryURL: temporaryURL,
            outputURL: outputURL
        )
        #endif
    }

    #if !os(Windows)
    private static func writeOnPOSIX(
        _ data: Data,
        temporaryURL: URL,
        outputURL: URL
    ) throws {
        let descriptor = temporaryURL.path.withCString {
            open($0, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        }
        guard descriptor >= 0 else {
            throw posixError(path: temporaryURL.path)
        }
        var shouldRemoveTemporaryFile = true
        defer {
            if shouldRemoveTemporaryFile {
                try? FileManager.default.removeItem(at: temporaryURL)
            }
        }

        let handle = FileHandle(
            fileDescriptor: descriptor,
            closeOnDealloc: false
        )
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }

        let result = temporaryURL.path.withCString { source in
            outputURL.path.withCString { destination in
                rename(source, destination)
            }
        }
        guard result == 0 else {
            throw posixError(path: outputURL.path)
        }
        shouldRemoveTemporaryFile = false
    }

    private static func posixError(path: String) -> NSError {
        NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSFilePathErrorKey: path]
        )
    }
    #endif

    #if os(Windows)
    private static func writeOnWindows(
        _ data: Data,
        temporaryURL: URL,
        outputURL: URL
    ) throws {

        // This protected DACL grants full access only to the file's owner.
        var securityDescriptor: PSECURITY_DESCRIPTOR?
        let securityDescriptorString = Array("D:P(A;;FA;;;OW)".utf16) + [0]
        let didConvertSecurityDescriptor = securityDescriptorString.withUnsafeBufferPointer {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                $0.baseAddress,
                DWORD(SDDL_REVISION_1),
                &securityDescriptor,
                nil
            )
        }
        guard didConvertSecurityDescriptor, let securityDescriptor else {
            throw windowsError(path: temporaryURL.path)
        }
        defer {
            LocalFree(securityDescriptor)
        }

        var securityAttributes = SECURITY_ATTRIBUTES()
        securityAttributes.nLength = DWORD(
            MemoryLayout<SECURITY_ATTRIBUTES>.size
        )
        securityAttributes.lpSecurityDescriptor = securityDescriptor
        securityAttributes.bInheritHandle = false

        let temporaryPath = Array(temporaryURL.path.utf16) + [0]
        let handle = temporaryPath.withUnsafeBufferPointer {
            CreateFileW(
                $0.baseAddress,
                DWORD(GENERIC_WRITE),
                0,
                &securityAttributes,
                DWORD(CREATE_NEW),
                DWORD(FILE_ATTRIBUTE_NORMAL)
                    | DWORD(FILE_FLAG_WRITE_THROUGH),
                nil
            )
        }
        guard let handle, handle != INVALID_HANDLE_VALUE else {
            throw windowsError(path: temporaryURL.path)
        }

        var shouldRemoveTemporaryFile = true
        defer {
            if shouldRemoveTemporaryFile {
                temporaryPath.withUnsafeBufferPointer {
                    _ = DeleteFileW($0.baseAddress)
                }
            }
        }

        do {
            try write(data, to: handle, path: temporaryURL.path)
            guard FlushFileBuffers(handle) else {
                throw windowsError(path: temporaryURL.path)
            }
            guard CloseHandle(handle) else {
                throw windowsError(path: temporaryURL.path)
            }
        } catch {
            _ = CloseHandle(handle)
            throw error
        }

        let outputPath = Array(outputURL.path.utf16) + [0]
        let moved = temporaryPath.withUnsafeBufferPointer { temporary in
            outputPath.withUnsafeBufferPointer { output in
                MoveFileExW(
                    temporary.baseAddress,
                    output.baseAddress,
                    DWORD(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
                )
            }
        }
        guard moved else {
            throw windowsError(path: outputURL.path)
        }
        shouldRemoveTemporaryFile = false
    }

    private static func write(
        _ data: Data,
        to handle: HANDLE,
        path: String
    ) throws {
        var storedError: NSError?
        data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let remaining = min(
                    bytes.count - offset,
                    Int(UInt32.max)
                )
                var written: DWORD = 0
                guard
                    WriteFile(
                        handle,
                        bytes.baseAddress?.advanced(by: offset),
                        DWORD(remaining),
                        &written,
                        nil
                    ),
                    written > 0
                else {
                    storedError = windowsError(path: path)
                    return
                }
                offset += Int(written)
            }
        }
        if let storedError {
            throw storedError
        }
    }

    private static func windowsError(path: String) -> NSError {
        NSError(
            domain: "NSWin32ErrorDomain",
            code: Int(GetLastError()),
            userInfo: [NSFilePathErrorKey: path]
        )
    }
    #endif
}
