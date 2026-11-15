import SwiftUI
import Observation

struct SDKVersion: Comparable, Hashable, Codable, CustomStringConvertible {
    var major: Int, minor: Int, patch: Int
    static let target = SDKVersion(major: 27, minor: 1, patch: 0)

    static func < (a: SDKVersion, b: SDKVersion) -> Bool {
        (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
    }
    var description: String { patch == 0 ? "\(major).\(minor)" : "\(major).\(minor).\(patch)" }
    var triple: [NSNumber] { [major, minor, patch].map { NSNumber(value: $0) } }
}

struct InstalledApp: Identifiable, Hashable {
    let id: String
    let name: String
    let signer: String
    let storeSigned: Bool
    let sdk: SDKVersion
    let container: String

    init(_ r: FDAppRecord) {
        container = r.containerUUID
        id = r.bundleID
        name = r.name
        signer = r.signer
        storeSigned = r.storeSigned
        sdk = SDKVersion(major: r.sdkMajor, minor: r.sdkMinor, patch: r.sdkPatch)
    }
}

enum AppFilter: String, CaseIterable, Identifiable {
    case all = "All", legacy = "Legacy SDK", forced = "Enabled", native = "Up to date"
    var title: LocalizedStringKey { LocalizedStringKey(rawValue) }
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .all: "square.grid.2x2"
        case .legacy: "clock.arrow.circlepath"
        case .forced: "bolt.fill"
        case .native: "checkmark.seal"
        }
    }
}

enum AppStatus {
    case native        // built with >= target SDK by its developer
    case forced        // we forced it and it's still forced
    case drifted       // we forced it but an update/rebuild reset it
    case legacy        // old SDK, not forced

    var label: LocalizedStringKey {
        switch self {
        case .native: "Native"
        case .forced: "Forced"
        case .drifted: "Re-apply needed"
        case .legacy: "Legacy SDK"
        }
    }
    var tint: Color {
        switch self {
        case .native: .secondary
        case .forced: .green
        case .drifted: .orange
        case .legacy: .blue
        }
    }
}

@MainActor
@Observable
final class AppCatalog {
    var apps: [InstalledApp] = []
    var loading = false
    var applying = false
    var errorMessage: String?
    var resultMessage: String?
    var storePath: String?
    var engineLog = ""
    var icons: [String: UIImage] = [:]

    /// What the user wants enabled (UI toggles).
    var selection: Set<String> = []
    /// Apps we have forced, as persisted after a successful apply.
    private(set) var forced: Set<String>
    /// Original SDK of each app before we touched it.
    private(set) var originals: [String: SDKVersion]

    private let defaults = UserDefaults.standard

    init() {
        forced = Set(defaults.stringArray(forKey: "forced") ?? [])
        if let data = defaults.data(forKey: "originals"),
           let decoded = try? JSONDecoder().decode([String: SDKVersion].self, from: data) {
            originals = decoded
        } else {
            originals = [:]
        }
        selection = forced
    }

    func status(of app: InstalledApp) -> AppStatus {
        if forced.contains(app.id) || originals[app.id] != nil {
            return app.sdk == .target ? .forced : (app.sdk < .target ? .drifted : .native)
        }
        return app.sdk >= .target ? .native : .legacy
    }

    func canToggle(_ app: InstalledApp) -> Bool {
        status(of: app) != .native
    }

    func apps(for filter: AppFilter, search: String) -> [InstalledApp] {
        apps.filter { app in
            let s = status(of: app)
            let passes: Bool = switch filter {
            case .all: true
            case .legacy: s == .legacy || s == .drifted
            case .forced: s == .forced || s == .drifted
            case .native: s == .native
            }
            guard passes else { return false }
            guard !search.isEmpty else { return true }
            return app.name.localizedCaseInsensitiveContains(search) || app.id.localizedCaseInsensitiveContains(search)
        }
    }

    func count(_ filter: AppFilter) -> Int { apps(for: filter, search: "").count }

    /// bundleID -> desired SDK for every record that has to change.
    var pendingChanges: [String: SDKVersion] {
        var changes: [String: SDKVersion] = [:]
        for app in apps {
            let wanted = selection.contains(app.id)
            if wanted, app.sdk < .target {
                changes[app.id] = .target
            } else if !wanted, let original = originals[app.id], app.sdk == .target, original != .target {
                changes[app.id] = original
            }
        }
        return changes
    }

    func binding(for app: InstalledApp) -> Binding<Bool> {
        Binding(
            get: { self.selection.contains(app.id) },
            set: { on in
                if on { self.selection.insert(app.id) } else { self.selection.remove(app.id) }
            })
    }

    func selectAllLegacy() {
        for app in apps where status(of: app) == .legacy || status(of: app) == .drifted { selection.insert(app.id) }
    }

    func deselectAll() { selection.removeAll() }

    func reload() async {
        loading = true
        errorMessage = nil
        defer { loading = false }
        let result: Result<[InstalledApp], Error> = await Task.detached {
            do {
                return .success(try FDEngine.shared.loadApps()
                    .filter { !($0.signer.isEmpty && $0.bundleID.hasPrefix("com.apple.")) }
                    .map(InstalledApp.init))
            } catch {
                return .failure(error)
            }
        }.value
        engineLog = FDEngine.shared.lastLog
        storePath = FDEngine.shared.storePath
        switch result {
        case .success(let list):
            apps = list
            reconcile()
            await loadIcons()
        case .failure(let error):
            errorMessage = error.localizedDescription
        }
    }

    /// Drop bookkeeping for apps that vanished, and adopt new originals after updates.
    private func reconcile() {
        let byID = Dictionary(uniqueKeysWithValues: apps.map { ($0.id, $0) })
        for (id, _) in originals where byID[id] == nil { originals[id] = nil }
        forced = forced.filter { byID[$0] != nil }
        for id in forced {
            if let app = byID[id], app.sdk != .target, app.sdk < .target { originals[id] = app.sdk }
        }
        selection = selection.filter { byID[$0] != nil }
        persist()
    }

    func apply() async {
        let changes = pendingChanges
        guard !changes.isEmpty else { return }
        applying = true
        defer { applying = false }
        // Record originals before the first force.
        for app in apps where changes[app.id] == .target && originals[app.id] == nil {
            originals[app.id] = app.sdk
        }
        persist()
        let payload = changes.mapValues { $0.triple }
        let result: Result<String, Error> = await Task.detached {
            do { return .success(try FDEngine.shared.applyVersions(payload, dryRun: false)) } catch { return .failure(error) }
        }.value
        engineLog = FDEngine.shared.lastLog
        switch result {
        case .success(let summary):
            for (id, version) in changes where version != .target { originals[id] = nil; forced.remove(id) }
            for (id, version) in changes where version == .target { forced.insert(id) }
            persist()
            resultMessage = summary + "\n" + String(localized: "Restart the iPhone Duo so apps reload the new interface.")
        case .failure(let error):
            errorMessage = error.localizedDescription
        }
        await reload()
    }

    private func persist() {
        defaults.set(Array(forced), forKey: "forced")
        defaults.set(try? JSONEncoder().encode(originals), forKey: "originals")
    }
}
