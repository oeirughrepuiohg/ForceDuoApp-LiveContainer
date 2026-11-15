import UIKit

/// Fetches app icons by bundle ID from the public App Store lookup API and caches them on disk.
/// Sideloaded apps that are not on the App Store fall back to the letter avatar.
enum IconStore {
    private static let missKey = "iconMisses"
    private static let retryAfter: TimeInterval = 3 * 24 * 3600

    static let directory: URL = {
        let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AppIcons", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    private static func file(_ id: String) -> URL {
        directory.appendingPathComponent(id.replacingOccurrences(of: "/", with: "_") + ".png")
    }

    static func cached(_ id: String) -> UIImage? {
        UIImage(contentsOfFile: file(id).path)
    }

    static func recentlyMissed(_ id: String) -> Bool {
        guard let misses = UserDefaults.standard.dictionary(forKey: missKey) as? [String: Double],
              let when = misses[id] else { return false }
        return Date().timeIntervalSince1970 - when < retryAfter
    }

    static func markMissed(_ ids: [String]) {
        guard !ids.isEmpty else { return }
        var misses = UserDefaults.standard.dictionary(forKey: missKey) as? [String: Double] ?? [:]
        let now = Date().timeIntervalSince1970
        for id in ids { misses[id] = now }
        UserDefaults.standard.set(misses, forKey: missKey)
    }

    private struct Lookup: Decodable {
        struct Item: Decodable {
            let bundleId: String?
            let artworkUrl512: String?
            let artworkUrl100: String?
            let artworkUrl60: String?
        }
        let results: [Item]
    }

    private static var storefronts: [String] {
        var list: [String] = []
        if let region = Locale.current.region?.identifier.lowercased() { list.append(region) }
        if !list.contains("us") { list.append("us") }
        return list
    }

    /// Looks up the bundle ID in the App Store and downloads a 180 px icon.
    static func fetch(_ id: String) async -> UIImage? {
        let session = URLSession.shared
        for country in storefronts {
            var components = URLComponents(string: "https://itunes.apple.com/lookup")!
            components.queryItems = [
                URLQueryItem(name: "bundleId", value: id),
                URLQueryItem(name: "country", value: country),
                URLQueryItem(name: "entity", value: "software"),
            ]
            guard let url = components.url,
                  let (data, _) = try? await session.data(from: url),
                  let item = (try? JSONDecoder().decode(Lookup.self, from: data))?.results
                    .first(where: { $0.bundleId == nil || $0.bundleId?.caseInsensitiveCompare(id) == .orderedSame }),
                  var artwork = item.artworkUrl512 ?? item.artworkUrl100 ?? item.artworkUrl60
            else { continue }
            if let range = artwork.range(of: #"\d+x\d+bb\.(jpg|png)$"#, options: .regularExpression) {
                artwork.replaceSubrange(range, with: "180x180bb.png")
            }
            guard let imageURL = URL(string: artwork),
                  let (imageData, _) = try? await session.data(from: imageURL),
                  let image = UIImage(data: imageData) else { continue }
            let format = UIGraphicsImageRendererFormat()
            format.scale = 1
            let icon = UIGraphicsImageRenderer(size: CGSize(width: 180, height: 180), format: format).image { _ in
                image.draw(in: CGRect(x: 0, y: 0, width: 180, height: 180))
            }
            if let png = icon.pngData() { try? png.write(to: file(id), options: .atomic) }
            return icon
        }
        return nil
    }
}

extension AppCatalog {
    func loadIcons() async {
        let ids = apps.map(\.id).filter { icons[$0] == nil }
        for id in ids {
            if let image = IconStore.cached(id) { icons[id] = image }
        }
        let remaining = ids.filter { icons[$0] == nil && !IconStore.recentlyMissed($0) }
        guard !remaining.isEmpty else { return }
        var misses: [String] = []
        await withTaskGroup(of: (String, UIImage?).self) { group in
            var queue = remaining.makeIterator()
            for _ in 0..<6 {
                guard let id = queue.next() else { break }
                group.addTask { (id, await IconStore.fetch(id)) }
            }
            while let (id, image) = await group.next() {
                if let image { icons[id] = image } else { misses.append(id) }
                if let next = queue.next() {
                    group.addTask { (next, await IconStore.fetch(next)) }
                }
            }
        }
        IconStore.markMissed(misses)
    }
}
