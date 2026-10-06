// ConMan's deliberately small Sparkle bridge.
//
// This target is kept out of the Rust update core. Sparkle is an AppKit/main
// actor API, so all of the object graph below is owned by the main actor and
// the exported C entry points synchronously hop to the main queue when called
// by the Rust worker. The callback's string pointers are valid only for the
// duration of one callback; the Rust side copies them immediately.

import AppKit
import Foundation
import Security
import Sparkle

private let stableFeed = "https://github.com/MarcoS0ft/ConMan/releases/latest/download/appcast-stable.xml"
private let devFeed = "https://github.com/MarcoS0ft/ConMan/releases/download/dev/appcast-dev.xml"
private let expectedBundleIdentifier = "com.marcos0ft.conman"
private let expectedTeamIdentifier = "2NZRF4HQT7"

public typealias ConManSparkleEventFn = @convention(c) (
    UnsafeMutableRawPointer?, UnsafePointer<ConManSparkleEvent>?
) -> Void

// Keep these declarations layout-compatible with updater/conman_sparkle.h.
// They are intentionally plain C-representable values: no Swift object or
// borrowed String crosses the bridge.
public struct ConManSparkleConfig {
    public var channel: UInt32
    public var automatic_download: UInt8
    public var reserved0: UInt8
    public var reserved1: UInt8
    public var reserved2: UInt8

    public init(channel: UInt32, automatic_download: UInt8) {
        self.channel = channel
        self.automatic_download = automatic_download
        self.reserved0 = 0
        self.reserved1 = 0
        self.reserved2 = 0
    }
}

public struct ConManSparkleEvent {
    public var generation: UInt64
    public var kind: UInt32
    public var manual: UInt8
    public var reserved0: UInt8
    public var reserved1: UInt8
    public var reserved2: UInt8
    public var received: UInt64
    public var total: UInt64
    public var revision: UInt64
    public var staging_token: UInt64
    public var version: UnsafePointer<CChar>?
    public var display_version: UnsafePointer<CChar>?
    public var release_notes_url: UnsafePointer<CChar>?
    public var info_url: UnsafePointer<CChar>?
    public var error_code: UInt32
    public var error_message: UnsafePointer<CChar>?
}

public struct ConManSparkleError {
    public var code: UInt32
    public var message: UnsafeMutablePointer<CChar>?
    public var message_capacity: Int
    public var message_length: Int
}

private enum EventKind {
    static let checkStarted: UInt32 = 1
    static let candidateFound: UInt32 = 2
    static let noCandidate: UInt32 = 3
    static let downloadStarted: UInt32 = 4
    static let downloadProgress: UInt32 = 5
    static let preparing: UInt32 = 6
    static let readyToInstall: UInt32 = 7
    static let cancelled: UInt32 = 8
    static let failed: UInt32 = 9
    static let installStarted: UInt32 = 10
    static let openReleasePage: UInt32 = 11
}

private enum BridgeErrorCode {
    static let invalidArgument: UInt32 = 1
    static let notStarted: UInt32 = 2
    static let alreadyStarted: UInt32 = 3
    static let unavailable: UInt32 = 4
    static let invalidState: UInt32 = 5
    static let sparkle: UInt32 = 100
    static let checkOnly: UInt32 = 101
    static let exhausted: UInt32 = 102
}

private enum Channel: UInt32 {
    case stable = 0
    case dev = 1

    var feedURL: String {
        switch self {
        case .stable: stableFeed
        case .dev: devFeed
        }
    }

    var sparkleName: String {
        switch self {
        case .stable: "stable"
        case .dev: "dev"
        }
    }
}

@MainActor
private final class ConManSparkleBridge: NSObject {
    let callback: ConManSparkleEventFn
    let context: UnsafeMutableRawPointer?
    let driver: ConManSparkleUserDriver
    let delegate: ConManSparkleUpdaterDelegate
    let updater: SPUUpdater

    private(set) var channel: Channel
    private(set) var automaticDownload: Bool
    // Generation zero is reserved for the idle bridge. The first check (and
    // every subsequent operation) therefore emits a non-zero generation that
    // the Rust adapter can correlate with its command stream.
    private(set) var generation: UInt64 = 0
    private(set) var started = false
    private(set) var disabled = false
    private var manualCheck = false
    private var latestItem: SUAppcastItem?

    init(
        config: UnsafePointer<ConManSparkleConfig>,
        callback: @escaping ConManSparkleEventFn,
        context: UnsafeMutableRawPointer?
    ) throws {
        guard let channel = Channel(rawValue: config.pointee.channel) else {
            throw BridgeFailure(code: BridgeErrorCode.invalidArgument, message: "unknown update channel")
        }
        guard config.pointee.automatic_download <= 1 else {
            throw BridgeFailure(code: BridgeErrorCode.invalidArgument, message: "automatic_download must be 0 or 1")
        }
        guard Bundle.main.bundleIdentifier == expectedBundleIdentifier else {
            throw BridgeFailure(code: BridgeErrorCode.unavailable, message: "ConMan bundle identifier is not recognized")
        }

        self.callback = callback
        self.context = context
        self.channel = channel
        self.automaticDownload = config.pointee.automatic_download != 0
        self.driver = ConManSparkleUserDriver(callback: callback, context: context)
        self.delegate = ConManSparkleUpdaterDelegate()
        self.updater = SPUUpdater(
            hostBundle: Bundle.main,
            applicationBundle: Bundle.main,
            userDriver: driver,
            delegate: delegate
        )
        super.init()
        delegate.owner = self
        driver.owner = self
        driver.automaticDownload = automaticDownload
    }

    func start(error output: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard !disabled else {
            writeError(output, code: BridgeErrorCode.exhausted, message: "updater is disabled for this process")
            return false
        }
        guard !started else {
            writeError(output, code: BridgeErrorCode.alreadyStarted, message: "updater already started")
            return false
        }
        updater.automaticallyChecksForUpdates = true
        updater.automaticallyDownloadsUpdates = automaticDownload
        updater.userAgentString = "ConMan/\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown") macOS"
        do {
            try updater.start()
            started = true
            return true
        } catch {
            writeSparkleError(error, into: output)
            disabled = true
            return false
        }
    }

    func setChannel(_ rawChannel: UInt32, error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard let next = Channel(rawValue: rawChannel) else {
            writeError(error, code: BridgeErrorCode.invalidArgument, message: "unknown update channel")
            return false
        }
        driver.cancelCurrentOperation()
        guard advanceGeneration(error: error) else { return false }
        channel = next
        latestItem = nil
        driver.invalidateForGenerationChange()
        if started { updater.resetUpdateCycle() }
        return true
    }

    func setAutomaticDownload(_ enabled: Bool, error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard !disabled else {
            writeError(error, code: BridgeErrorCode.exhausted, message: "updater is disabled for this process")
            return false
        }
        driver.cancelCurrentOperation()
        guard advanceGeneration(error: error) else { return false }
        automaticDownload = enabled
        driver.automaticDownload = enabled
        updater.automaticallyDownloadsUpdates = enabled
        driver.invalidateForGenerationChange()
        if started { updater.resetUpdateCycleAfterShortDelay() }
        return true
    }

    func check(manual: Bool, error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard !disabled else {
            writeError(error, code: BridgeErrorCode.exhausted, message: "updater is disabled for this process")
            return false
        }
        guard started else {
            writeError(error, code: BridgeErrorCode.notStarted, message: "updater has not started")
            return false
        }
        guard advanceGeneration(error: error) else { return false }
        manualCheck = manual
        latestItem = nil
        driver.beginGeneration(generation, manual: manual)
        if manual {
            updater.checkForUpdates()
        } else {
            updater.checkForUpdatesInBackground()
        }
        return true
    }

    func cancel(error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard !disabled else {
            writeError(error, code: BridgeErrorCode.exhausted, message: "updater is disabled for this process")
            return false
        }
        driver.cancelCurrentOperation()
        driver.invalidateInstallReply()
        emit(kind: EventKind.cancelled)
        return true
    }

    func installAndRelaunch(error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard !disabled else {
            writeError(error, code: BridgeErrorCode.exhausted, message: "updater is disabled for this process")
            return false
        }
        guard isProductionBundleEligibleForReplacement() else {
            writeError(
                error,
                code: BridgeErrorCode.checkOnly,
                message: "this local or ad-hoc ConMan bundle is check-only"
            )
            return false
        }
        guard let install = driver.takeInstallReply() else {
            writeError(error, code: BridgeErrorCode.invalidState, message: "no staged Sparkle update is ready")
            return false
        }
        emit(kind: EventKind.installStarted)
        install()
        return true
    }

    func candidate(_ item: SUAppcastItem) {
        latestItem = item
        guard !item.isInformationOnlyUpdate else {
            emit(
                kind: EventKind.openReleasePage,
                version: item.versionString,
                displayVersion: item.displayVersionString,
                releaseNotesURL: item.releaseNotesURL?.absoluteString,
                infoURL: item.infoURL?.absoluteString
            )
            return
        }
        guard item.fileURL != nil, item.contentLength > 0 else {
            fail(code: BridgeErrorCode.sparkle, message: "Sparkle appcast item has no complete DMG enclosure")
            return
        }
        guard let revision = UInt64(item.versionString) else {
            fail(code: BridgeErrorCode.sparkle, message: "Sparkle appcast revision is not numeric")
            return
        }
        emit(
            kind: EventKind.candidateFound,
            total: item.contentLength,
            revision: revision,
            version: item.versionString,
            displayVersion: item.displayVersionString,
            releaseNotesURL: item.releaseNotesURL?.absoluteString,
            infoURL: item.infoURL?.absoluteString
        )
    }

    func noCandidate(_ errorValue: Error?) {
        if manualCheck {
            emit(kind: EventKind.noCandidate)
        }
        if let errorValue, !isNoUpdateError(errorValue) {
            fail(code: errorCode(errorValue), message: sanitizedError(errorValue))
        }
    }

    func failed(_ errorValue: Error) {
        driver.invalidateInstallReply()
        fail(code: errorCode(errorValue), message: sanitizedError(errorValue))
    }

    func invalidateInstallReply() {
        driver.invalidateInstallReply()
    }

    func shutdown() {
        disabled = true
        delegate.owner = nil
        driver.shutdown()
        latestItem = nil
    }

    func feedURL() -> String { channel.feedURL }

    func allowedChannels() -> Set<String> { [channel.sparkleName] }

    private func advanceGeneration(error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
        guard generation < UInt64.max else {
            disabled = true
            writeError(error, code: BridgeErrorCode.exhausted, message: "update generation exhausted")
            return false
        }
        generation += 1
        return true
    }

    private func fail(code: UInt32, message: String) {
        emit(kind: EventKind.failed, errorCode: code, errorMessage: message)
    }

    fileprivate func emit(
        kind: UInt32,
        manual: Bool = false,
        received: UInt64 = 0,
        total: UInt64 = 0,
        revision: UInt64 = 0,
        stagingToken: UInt64 = 0,
        version: String = "",
        displayVersion: String = "",
        releaseNotesURL: String? = nil,
        infoURL: String? = nil,
        errorCode: UInt32 = 0,
        errorMessage: String = ""
    ) {
        let notes = releaseNotesURL ?? ""
        let info = infoURL ?? ""
        version.withCString { versionPointer in
            displayVersion.withCString { displayPointer in
                notes.withCString { notesPointer in
                    info.withCString { infoPointer in
                        errorMessage.withCString { errorPointer in
                            var event = ConManSparkleEvent(
                                generation: generation,
                                kind: kind,
                                manual: manual ? 1 : 0,
                                reserved0: 0,
                                reserved1: 0,
                                reserved2: 0,
                                received: received,
                                total: total,
                                revision: revision,
                                staging_token: stagingToken,
                                version: versionPointer,
                                display_version: displayPointer,
                                release_notes_url: notesPointer,
                                info_url: infoPointer,
                                error_code: errorCode,
                                error_message: errorPointer
                            )
                            withUnsafePointer(to: &event) { callback(context, $0) }
                        }
                    }
                }
            }
        }
    }

    private func writeSparkleError(_ value: Error, into output: UnsafeMutablePointer<ConManSparkleError>?) {
        writeError(output, code: errorCode(value), message: sanitizedError(value))
    }

    private func isNoUpdateError(_ value: Error) -> Bool {
        let nsError = value as NSError
        return nsError.domain == SUSparkleErrorDomain && nsError.code == SUNoUpdateError
    }

    private func errorCode(_ value: Error) -> UInt32 {
        let code = (value as NSError).code
        return code < 0 ? UInt32(min(-code, Int(Int32.max))) : UInt32(min(code, Int(UInt32.max)))
    }

    private func sanitizedError(_ value: Error) -> String {
        let raw = String(describing: value)
        let safe = raw.map { character -> Character in
            if character.isNewline || character.isWhitespace { return " " }
            if character.asciiValue.map({ $0 < 0x20 || $0 == 0x7f }) == true { return "?" }
            return character
        }
        return String(safe.prefix(240))
    }

    private func isProductionBundleEligibleForReplacement() -> Bool {
        let bundleURL = Bundle.main.bundleURL.standardizedFileURL
        let path = bundleURL.path
        guard path.hasSuffix(".app"), !path.contains("/AppTranslocation/") else { return false }
        guard FileManager.default.isWritableFile(atPath: path) else { return false }
        guard FileManager.default.isWritableFile(atPath: bundleURL.deletingLastPathComponent().path) else { return false }
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return false }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String
        else { return false }
        return identifier == expectedBundleIdentifier && team == expectedTeamIdentifier
    }
}

@MainActor
private final class ConManSparkleUserDriver: NSObject, SPUUserDriver {
    weak var owner: ConManSparkleBridge?
    var automaticDownload = true

    private let callback: ConManSparkleEventFn
    private let context: UnsafeMutableRawPointer?
    private var currentCancellation: (() -> Void)?
    private var downloadReceived: UInt64 = 0
    private var downloadTotal: UInt64 = 0
    private var installReply: (() -> Void)?
    private var installContinuation: CheckedContinuation<SPUUserUpdateChoice, Never>?

    init(callback: @escaping ConManSparkleEventFn, context: UnsafeMutableRawPointer?) {
        self.callback = callback
        self.context = context
    }

    func show(_ request: SPUUpdatePermissionRequest) async -> SUUpdatePermissionResponse {
        SUUpdatePermissionResponse(
            automaticUpdateChecks: true,
            automaticUpdateDownloading: NSNumber(value: automaticDownload),
            sendSystemProfile: false
        )
    }

    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) {
        currentCancellation = cancellation
        owner?.emit(kind: EventKind.checkStarted, manual: true)
    }

    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState) async -> SPUUserUpdateChoice {
        // The shared ConMan capsule owns presentation. Returning install here
        // only authorizes Sparkle to download when the common preference allows
        // it; it never authorizes replacement. Replacement is deferred until
        // installAndRelaunch consumes the retained reply below.
        guard !appcastItem.isInformationOnlyUpdate else { return .dismiss }
        guard automaticDownload || state.userInitiated else { return .dismiss }
        return .install
    }

    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {}

    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: any Error) {}

    func showUpdateNotFoundWithError(_ error: any Error) async {
        owner?.noCandidate(error)
    }

    func showUpdaterError(_ error: any Error) async {
        owner?.failed(error)
    }

    func showDownloadInitiated(cancellation: @escaping () -> Void) {
        currentCancellation = cancellation
        downloadReceived = 0
        downloadTotal = 0
        owner?.emit(kind: EventKind.downloadStarted)
    }

    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {
        downloadTotal = expectedContentLength
        owner?.emit(kind: EventKind.downloadProgress, received: downloadReceived, total: downloadTotal)
    }

    func showDownloadDidReceiveData(ofLength length: UInt64) {
        let (next, overflow) = downloadReceived.addingReportingOverflow(length)
        downloadReceived = overflow ? UInt64.max : next
        owner?.emit(kind: EventKind.downloadProgress, received: downloadReceived, total: downloadTotal)
    }

    func showDownloadDidStartExtractingUpdate() {
        owner?.emit(kind: EventKind.preparing, received: downloadReceived, total: downloadTotal)
    }

    func showExtractionReceivedProgress(_ progress: Double) {
        let bounded = min(max(progress, 0), 1)
        owner?.emit(kind: EventKind.preparing, received: UInt64(bounded * 1_000_000), total: 1_000_000)
    }

    func showReadyToInstallAndRelaunch() async -> SPUUserUpdateChoice {
        guard let owner else { return .dismiss }
        owner.emit(kind: EventKind.readyToInstall, stagingToken: owner.generation)
        return await withCheckedContinuation { continuation in
            // Sparkle invokes this method once for one update generation. If a
            // future Sparkle release violates that contract, dismiss the old
            // continuation before retaining the new one rather than resuming
            // two choices for one update.
            installContinuation?.resume(returning: .dismiss)
            installReply = nil
            installContinuation = continuation
        }
    }

    func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        owner?.emit(kind: EventKind.installStarted)
    }

    func showUpdateInstalledAndRelaunched(_ relaunched: Bool) async {}

    func dismissUpdateInstallation() {
        currentCancellation = nil
        installContinuation?.resume(returning: .dismiss)
        installContinuation = nil
        installReply = nil
    }

    func beginGeneration(_ generation: UInt64, manual: Bool) {
        currentCancellation = nil
        downloadReceived = 0
        downloadTotal = 0
        // `manual` is carried by the bridge's check-start event; this method is
        // intentionally otherwise state-free so Sparkle remains authoritative.
        _ = (generation, manual)
    }

    func cancelCurrentOperation() {
        currentCancellation?()
        currentCancellation = nil
    }

    func invalidateForGenerationChange() {
        currentCancellation = nil
        downloadReceived = 0
        downloadTotal = 0
        invalidateInstallReply()
    }

    func invalidateInstallReply() {
        installReply = nil
        installContinuation?.resume(returning: .dismiss)
        installContinuation = nil
    }

    func takeInstallReply() -> (() -> Void)? {
        if let reply = installReply {
            installReply = nil
            return reply
        }
        if let continuation = installContinuation {
            installContinuation = nil
            return { continuation.resume(returning: .install) }
        }
        return nil
    }

    func retainInstallReply(_ reply: @escaping () -> Void) {
        installContinuation?.resume(returning: .dismiss)
        installContinuation = nil
        installReply = reply
    }

    func shutdown() {
        currentCancellation = nil
        downloadReceived = 0
        downloadTotal = 0
        invalidateInstallReply()
    }
}

@MainActor
private final class ConManSparkleUpdaterDelegate: NSObject, SPUUpdaterDelegate {
    weak var owner: ConManSparkleBridge?

    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {}

    func allowedChannels(for updater: SPUUpdater) -> Set<String> {
        owner?.allowedChannels() ?? []
    }

    func feedURLString(for updater: SPUUpdater) -> String? {
        owner?.feedURL()
    }

    func updaterShouldPromptForPermissionToCheckForUpdates(_ updater: SPUUpdater) -> Bool { false }

    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        owner?.candidate(item)
    }

    func updaterDidNotFindUpdate(_ updater: SPUUpdater, error: Error) {
        owner?.noCandidate(error)
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: any Error) {
        owner?.failed(error)
    }

    func updater(_ updater: SPUUpdater, userDidMakeChoice choice: SPUUserUpdateChoice, forUpdate updateItem: SUAppcastItem, state: SPUUserUpdateState) {
        if choice != .install { owner?.invalidateInstallReply() }
    }

    func updater(_ updater: SPUUpdater, failedToDownloadUpdate item: SUAppcastItem, error: Error) {
        owner?.failed(error)
    }

    func userDidCancelDownload(_ updater: SPUUpdater) {
        owner?.emit(kind: EventKind.cancelled)
    }

    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem, immediateInstallationBlock: @escaping () -> Void) -> Bool {
        guard let owner else { return false }
        owner.candidate(item)
        owner.driver.retainInstallReply(immediateInstallationBlock)
        owner.emit(kind: EventKind.readyToInstall, stagingToken: owner.generation)
        return true
    }

    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        owner?.emit(kind: EventKind.installStarted)
    }

    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: (any Error)?) {
        if let error { owner?.failed(error) }
    }
}

private struct BridgeFailure: Error {
    let code: UInt32
    let message: String
}

private func writeError(_ output: UnsafeMutablePointer<ConManSparkleError>?, code: UInt32, message: String) {
    guard let output else { return }
    output.pointee.code = code
    let safe = sanitizedBridgeMessage(message, limit: 240)
    let bytes = Array(safe.utf8)
    output.pointee.message_length = 0
    guard let destination = output.pointee.message, output.pointee.message_capacity > 0 else { return }
    let count = min(bytes.count, output.pointee.message_capacity - 1)
    for index in 0..<count { destination[index] = CChar(bitPattern: bytes[index]) }
    destination[count] = 0
    output.pointee.message_length = count
}

private func writeSparkleError(_ value: Error, into output: UnsafeMutablePointer<ConManSparkleError>?) {
    let nsError = value as NSError
    let message = sanitizedBridgeMessage(String(describing: value), limit: 240)
    let code = nsError.code < 0 ? UInt32(min(-nsError.code, Int(Int32.max))) : UInt32(min(nsError.code, Int(UInt32.max)))
    writeError(output, code: code, message: message)
}

/// Keep diagnostics bounded and single-line at the C boundary. Sparkle error
/// descriptions can contain URLs or filesystem paths; they are useful for a
/// local error message but must never be allowed to inject control characters
/// into logs or shared update state.
private func sanitizedBridgeMessage(_ value: String, limit: Int) -> String {
    let safe = value.map { character -> Character in
        if character.isNewline || character.isWhitespace { return " " }
        if character.asciiValue.map({ $0 < 0x20 || $0 == 0x7f }) == true { return "?" }
        return character
    }
    return String(safe.prefix(limit))
}

private func onMain<T>(_ body: @escaping @MainActor () -> T) -> T {
    if Thread.isMainThread {
        return MainActor.assumeIsolated(body)
    }
    return DispatchQueue.main.sync { MainActor.assumeIsolated(body) }
}

@_cdecl("conman_sparkle_create")
public func conman_sparkle_create(
    _ config: UnsafePointer<ConManSparkleConfig>?,
    _ callback: ConManSparkleEventFn?,
    _ context: UnsafeMutableRawPointer?,
    _ output: UnsafeMutablePointer<ConManSparkleError>?
) -> UnsafeMutableRawPointer? {
    guard let config, let callback else {
        writeError(output, code: BridgeErrorCode.invalidArgument, message: "config and callback are required")
        return nil
    }
    return onMain {
        do {
            let bridge = try ConManSparkleBridge(config: config, callback: callback, context: context)
            return Unmanaged.passRetained(bridge).toOpaque()
        } catch let failure as BridgeFailure {
            writeError(output, code: failure.code, message: failure.message)
            return nil
        } catch {
            writeSparkleError(error, into: output)
            return nil
        }
    }
}

@_cdecl("conman_sparkle_start")
public func conman_sparkle_start(_ handle: UnsafeMutableRawPointer?, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().start(error: error) }
}

@_cdecl("conman_sparkle_set_channel")
public func conman_sparkle_set_channel(_ handle: UnsafeMutableRawPointer?, _ channel: UInt32, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().setChannel(channel, error: error) }
}

@_cdecl("conman_sparkle_set_automatic_download")
public func conman_sparkle_set_automatic_download(_ handle: UnsafeMutableRawPointer?, _ enabled: Bool, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().setAutomaticDownload(enabled, error: error) }
}

@_cdecl("conman_sparkle_check")
public func conman_sparkle_check(_ handle: UnsafeMutableRawPointer?, _ manual: Bool, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().check(manual: manual, error: error) }
}

@_cdecl("conman_sparkle_cancel")
public func conman_sparkle_cancel(_ handle: UnsafeMutableRawPointer?, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().cancel(error: error) }
}

@_cdecl("conman_sparkle_install_and_relaunch")
public func conman_sparkle_install_and_relaunch(_ handle: UnsafeMutableRawPointer?, _ error: UnsafeMutablePointer<ConManSparkleError>?) -> Bool {
    guard let handle else { writeError(error, code: BridgeErrorCode.invalidArgument, message: "null updater handle"); return false }
    return onMain { Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeUnretainedValue().installAndRelaunch(error: error) }
}

@_cdecl("conman_sparkle_destroy")
public func conman_sparkle_destroy(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else { return }
    onMain {
        let bridge = Unmanaged<ConManSparkleBridge>.fromOpaque(handle).takeRetainedValue()
        bridge.shutdown()
    }
}
