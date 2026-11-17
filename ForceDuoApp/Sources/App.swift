import SwiftUI

@main
struct ForceDuoApp: App {
    @State private var catalog = AppCatalog()

    init() {
        let args = ProcessInfo.processInfo.arguments
        if args.contains("--fd-rescan") { UserDefaults.standard.removeObject(forKey: "FDStoreDirectory") }
        if let arg = args.first(where: { $0.hasPrefix("--fd-dryrun=") }) {
            let id = String(arg.dropFirst("--fd-dryrun=".count))
            DispatchQueue.global().async {
                let text: String
                do {
                    text = try FDEngine.shared.applyVersions([id: SDKVersion.target.triple], dryRun: true)
                } catch {
                    text = "FAILED: \(error.localizedDescription)"
                }
                FileHandle.standardError.write(Data(("FD_REPORT\n" + text + "\n" + FDEngine.shared.lastLog + "\nEND_FD_REPORT\n").utf8))
                exit(0)
            }
        }
        if let arg = args.first(where: { $0.hasPrefix("--fd-probe=") }) {
            let path = String(arg.dropFirst("--fd-probe=".count))
            var method: NSString?
            let handle = FDGrantAccess(path, &method)
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: path).count) ?? -1
            let text = "group=\(FDResolvedAppGroup() ?? "nil") handle=\(handle) method=\(method ?? "-") entries=\(entries)\n" + FDLastGrantDiagnostic()
            FileHandle.standardError.write(Data(("FD_REPORT\n" + text + "\nEND_FD_REPORT\n").utf8))
            exit(0)
        }
        if args.contains("--fd-dump") {
            DispatchQueue.global().async {
                let text: String
                do { text = try FDEngine.shared.exportDiagnostics() } catch {
                    text = "FAILED: \(error.localizedDescription)\n\(FDEngine.shared.lastLog)"
                }
                FileHandle.standardError.write(Data(("FD_REPORT\n" + text + "\nEND_FD_REPORT\n").utf8))
                exit(0)
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(catalog)
                .task {
                    let debugRun = ProcessInfo.processInfo.arguments.contains { $0.hasPrefix("--fd-dryrun=") || $0 == "--fd-dump" || $0.hasPrefix("--fd-probe=") }
                    if !debugRun { await catalog.reload() }
                }
        }
    }
}

struct RootView: View {
    @Environment(AppCatalog.self) private var catalog
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var filter: AppFilter? = .legacy
    @State private var column: NavigationSplitViewColumn = .detail
    @State private var visibility: NavigationSplitViewVisibility = .automatic

    var body: some View {
        NavigationSplitView(columnVisibility: $visibility, preferredCompactColumn: $column) {
            Sidebar(filter: $filter)
                .navigationSplitViewColumnWidth(min: 280, ideal: 320, max: 380)
        } detail: {
            NavigationStack {
                AppListView(filter: filter ?? .all, filterBinding: $filter)
            }
        }
        .navigationSplitViewStyle(.balanced)
        .alert("Error", isPresented: Binding(get: { catalog.errorMessage != nil }, set: { if !$0 { catalog.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(catalog.errorMessage ?? "")
        }
        .sheet(isPresented: Binding(get: { catalog.resultMessage != nil }, set: { if !$0 { catalog.resultMessage = nil } })) {
            ResultSheet(message: catalog.resultMessage ?? "")
        }
    }
}

// MARK: - Sidebar (visible beside the list when the Duo is unfolded)

struct Sidebar: View {
    @Environment(AppCatalog.self) private var catalog
    @Binding var filter: AppFilter?

    var body: some View {
        List(selection: $filter) {
            Section {
                HeaderCard()
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }
            Section("Filters") {
                ForEach(AppFilter.allCases) { item in
                    NavigationLink(value: item) {
                        Label(item.title, systemImage: item.symbol)
                            .badge(catalog.count(item))
                    }
                }
            }
            Section("Device") {
                LabeledContent("Model", value: FDEngine.deviceModel())
                LabeledContent("iOS", value: UIDevice.current.systemVersion)
                LabeledContent("Target SDK", value: SDKVersion.target.description)
                if let path = catalog.storePath {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Cache LaunchServices").font(.caption).foregroundStyle(.secondary)
                        Text(path).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
                NavigationLink("Technical log") { LogView() }
            }
            Section("Credits") {
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: "worse_query").font(.subheadline.monospaced().weight(.semibold))
                    Text("Sandbox extension PoC by Taj C (forcequit), licensed under GPL-3.0.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Force Duo")
    }
}

struct HeaderCard: View {
    @Environment(AppCatalog.self) private var catalog

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "iphone.gen3.radiowaves.left.and.right")
                    .font(.title2)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text("The iOS 27 look for every app").font(.headline)
                    Text("Force SDK \(SDKVersion.target.description) via LaunchServices").font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack(spacing: 8) {
                StatPill(value: catalog.count(.legacy), title: "Legacy SDK", tint: .blue)
                StatPill(value: catalog.count(.forced), title: "Enabled", tint: .green)
                StatPill(value: catalog.count(.native), title: "Native", tint: .secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 24))
        .padding(.vertical, 6)
    }
}

struct StatPill: View {
    let value: Int, title: LocalizedStringKey, tint: Color
    var body: some View {
        VStack(spacing: 2) {
            Text("\(value)").font(.title3.bold().monospacedDigit()).foregroundStyle(tint)
            Text(title).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .glassEffect(.regular.tint(tint.opacity(0.12)), in: .rect(cornerRadius: 14))
    }
}

// MARK: - App list

struct AppListView: View {
    @Environment(AppCatalog.self) private var catalog
    @Environment(\.horizontalSizeClass) private var sizeClass
    let filter: AppFilter
    @Binding var filterBinding: AppFilter?
    @State private var search = ""
    @State private var confirm = false

    var body: some View {
        let items = catalog.apps(for: filter, search: search)
        List {
            if sizeClass == .compact {
                Section {
                    Picker("Filters", selection: Binding(get: { filter }, set: { filterBinding = $0 })) {
                        ForEach(AppFilter.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
            }
            if catalog.loading && catalog.apps.isEmpty {
                HStack { Spacer(); ProgressView("Reading the app cache…"); Spacer() }
                    .listRowBackground(Color.clear)
            } else if items.isEmpty {
                ContentUnavailableView(search.isEmpty ? LocalizedStringKey("No apps") : LocalizedStringKey("No results"),
                                       systemImage: filter.symbol,
                                       description: Text(catalog.apps.isEmpty ? LocalizedStringKey("The app list could not be read yet.") : LocalizedStringKey("Try another filter.")))
                    .listRowBackground(Color.clear)
            } else {
                Section {
                    ForEach(items) { app in
                        AppRow(app: app)
                    }
                } footer: {
                    Text("Turn an app on to force SDK \(SDKVersion.target.description). Turn a forced app off to restore its original SDK.")
                }
            }
        }
        .contentMargins(.bottom, 90, for: .scrollContent)
        .navigationTitle(filter.title)
        .searchable(text: $search, prompt: Text("Search apps or bundle IDs"))
        .refreshable { await catalog.reload() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Select all legacy apps", systemImage: "checklist") { catalog.selectAllLegacy() }
                    Button("Deselect all", systemImage: "xmark.circle") { catalog.deselectAll() }
                    Divider()
                    Button("Reload", systemImage: "arrow.clockwise") { Task { await catalog.reload() } }
                    Button("Export diagnostics", systemImage: "stethoscope") {
                        Task.detached { _ = try? FDEngine.shared.exportDiagnostics() }
                    }
                } label: {
                    Image(systemName: "ellipsis")
                }
            }
        }
        .safeAreaInset(edge: .bottom) { ApplyBar(confirm: $confirm) }
        .confirmationDialog("Write to the LaunchServices cache?", isPresented: $confirm, titleVisibility: .visible) {
            Button("Apply \(catalog.pendingChanges.count) changes") { Task { await catalog.apply() } }
        } message: {
            Text("A copy of the cache is saved to Documents/Backups before writing. Restart the phone afterwards.")
        }
        .sensoryFeedback(.success, trigger: catalog.forced)
    }
}

struct AppRow: View {
    @Environment(AppCatalog.self) private var catalog
    let app: InstalledApp

    var body: some View {
        let status = catalog.status(of: app)
        let wanted = catalog.selection.contains(app.id)
        HStack(spacing: 12) {
            AppIcon(id: app.id, name: app.name)
            VStack(alignment: .leading, spacing: 3) {
                Text(app.name).font(.body.weight(.medium)).lineLimit(1)
                Text(app.id).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                HStack(spacing: 6) {
                    Tag(text: Text(verbatim: "SDK \(app.sdk)"), tint: .secondary)
                    Tag(text: Text(status.label), tint: status.tint)
                    if !app.storeSigned { Tag(text: Text("Sideload"), tint: .purple) }
                    if wanted && app.sdk < .target { Tag(text: Text(verbatim: "→ \(SDKVersion.target)"), tint: .green) }
                    if !wanted && status == .forced { Tag(text: Text("→ original"), tint: .red) }
                }
            }
            Spacer(minLength: 8)
            Toggle("", isOn: catalog.binding(for: app))
                .labelsHidden()
                .disabled(!catalog.canToggle(app))
        }
        .padding(.vertical, 2)
        .contentShape(.rect)
        .onTapGesture {
            guard catalog.canToggle(app) else { return }
            catalog.binding(for: app).wrappedValue.toggle()
        }
    }
}

struct Tag: View {
    let text: Text, tint: Color
    var body: some View {
        text
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .foregroundStyle(tint)
            .background(tint.opacity(0.14), in: .capsule)
    }
}

struct AppIcon: View {
    @Environment(AppCatalog.self) private var catalog
    let id: String, name: String
    var body: some View {
        Group {
            if let image = catalog.icons[id] {
                Image(uiImage: image).resizable()
            } else {
                ZStack {
                    LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
                    Text(String(name.prefix(1)).uppercased()).font(.title3.bold()).foregroundStyle(.white)
                }
            }
        }
        .frame(width: 44, height: 44)
        .clipShape(.rect(cornerRadius: 10, style: .continuous))
    }
}

struct ApplyBar: View {
    @Environment(AppCatalog.self) private var catalog
    @Binding var confirm: Bool

    var body: some View {
        let pending = catalog.pendingChanges
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(pending.isEmpty ? LocalizedStringKey("No changes") : LocalizedStringKey("\(pending.count) pending changes"))
                    .font(.subheadline.weight(.semibold))
                Text("\(catalog.selection.count) apps selected").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                confirm = true
            } label: {
                if catalog.applying {
                    ProgressView()
                } else {
                    Label("Apply", systemImage: "bolt.fill").font(.headline)
                }
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .disabled(pending.isEmpty || catalog.applying || catalog.loading)
        }
        .padding(.horizontal, 18).padding(.vertical, 12)
        .glassEffect(.regular, in: .capsule)
        .padding(.horizontal, 16).padding(.bottom, 8)
    }
}

struct ResultSheet: View {
    let message: String
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Label("Done", systemImage: "checkmark.seal.fill")
                        .font(.title2.bold()).foregroundStyle(.green)
                    Text(message).textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Close") { dismiss() } } }
        }
        .presentationDetents([.medium, .large])
    }
}

struct LogView: View {
    @Environment(AppCatalog.self) private var catalog
    var body: some View {
        ScrollView {
            Text(catalog.engineLog.isEmpty ? String(localized: "No log yet.") : catalog.engineLog)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .navigationTitle("Log")
    }
}
