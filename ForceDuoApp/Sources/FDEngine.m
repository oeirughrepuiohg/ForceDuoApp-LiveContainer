#import "FDEngine.h"
#import "worse_query.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include <objc/message.h>
#include <objc/runtime.h>

NSString *const FDAppGroup = @"group.com.34306.forceDuo";
// Guest groups are virtualized by LiveContainer. Only its host group can be
// used with containermanagerd. Resolve dynamically to keep native installs independent.
static NSString *fdAccessGroup(void) {
    if (!getenv("LC_HOME_PATH")) return FDAppGroup;
    Class host = NSClassFromString(@"LCSharedUtils");
    SEL selector = NSSelectorFromString(@"appGroupID");
    if (![host respondsToSelector:selector]) return nil;
    id group = ((id (*)(id, SEL))objc_msgSend)(host, selector);
    if (![group isKindOfClass:NSString.class] || ![group hasPrefix:@"group."]) return nil;
    NSURL *root = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:group];
    // Reject virtual guest folders: they cannot satisfy the system query.
    NSString *path = root.path.stringByStandardizingPath;
    if (![path hasPrefix:@"/private/var/mobile/Containers/Shared/AppGroup/"] &&
        ![path hasPrefix:@"/var/mobile/Containers/Shared/AppGroup/"]) return nil;
    return group;
}

NSErrorDomain const FDErrorDomain = @"ForceDuo";

// LaunchServices "Bundle" record layouts (CoreServicesStore v2), keyed by record size.
// 604 bytes: iOS 27.3. 592 bytes: iOS 27.1, verified against this Duo's store.
typedef struct {
    uint32_t size;
    NSUInteger identifier, identifier2, kind, sdk, name, name2, signer, bundleName, placeholder;
} FDLayout;
static const FDLayout kLayouts[] = {
    {604, 0x0c, 0x18, 0x1c, 0x48, 0x78, 0x08, 0x88, 0x144, 0x244},
    {592, 0x0c, 0x14, 0x18, 0x44, 0x74, 0x08, 0x84, 0x140, 0x23c},
};
static const FDLayout *layoutForSize(uint32_t size) {
    for (size_t i = 0; i < sizeof(kLayouts) / sizeof(kLayouts[0]); ++i)
        if (kLayouts[i].size == size) return &kLayouts[i];
    return NULL;
}
static const NSUInteger kMaxStore = 64 * 1024 * 1024;
static NSString *const kStoreDirKey = @"FDStoreDirectory";

static NSError *fdError(NSString *message) {
    return [NSError errorWithDomain:FDErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: message}];
}

#pragma mark - Record

@implementation FDAppRecord
- (BOOL)storeSigned {
    return [self.signer isEqualToString:@"Apple iPhone OS Application Signing"] ||
           [self.signer isEqualToString:@"TestFlight Beta Distribution"];
}
@end

#pragma mark - Store parsing

static uint32_t fd_u32(const uint8_t *bytes, NSUInteger offset) {
    uint32_t value;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static NSDictionary<NSNumber *, NSNumber *> *fdHashTableEntries(NSData *store, NSUInteger unit) {
    const uint8_t *bytes = store.bytes;
    NSUInteger length = store.length;
    if (unit > length || length - unit < 0x50 || fd_u32(bytes, unit + 4) < 0x48) return nil;
    NSUInteger hash = fd_u32(bytes, unit + 0x4c);
    if (!hash || hash > length || length - hash < 4) return nil;
    NSUInteger buckets = fd_u32(bytes, hash);
    if (buckets > (length - hash - 4) / 8) return nil;
    NSMutableDictionary *units = [NSMutableDictionary dictionary];
    for (NSUInteger bucket = 0; bucket < buckets; ++bucket) {
        NSUInteger header = hash + 4 + bucket * 8;
        NSUInteger count = fd_u32(bytes, header);
        if (!count) continue;
        NSUInteger start = fd_u32(bytes, header + 4);
        if (start > length || count > (length - start) / 8) return nil;
        for (NSUInteger index = 0; index < count; ++index) {
            NSUInteger slot = start + index * 8;
            uint32_t key = fd_u32(bytes, slot);
            NSUInteger offset = fd_u32(bytes, slot + 4);
            if (offset == UINT32_MAX) continue;
            if (offset > length || length - offset < 8 || fd_u32(bytes, offset + 4) > length - offset - 8) return nil;
            if (units[@(key)] && ![units[@(key)] isEqual:@(offset)]) return nil;
            units[@(key)] = @(offset);
        }
    }
    return units;
}

static NSString *fdUnitText(NSData *store, NSUInteger unit, NSUInteger maximum) {
    const uint8_t *bytes = store.bytes;
    NSUInteger size = MIN(fd_u32(bytes, unit + 4), maximum);
    while (size && bytes[unit + 8 + size - 1] == 0) --size;
    return [[NSString alloc] initWithBytes:bytes + unit + 8 length:size encoding:NSUTF8StringEncoding];
}

static NSString *fdRecordText(NSData *store, NSDictionary *strings, NSUInteger body, NSUInteger field) {
    uint32_t key = fd_u32(store.bytes, body + field);
    if (key & 1) {
        const char alphabet[] = "\0 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char result[5];
        NSUInteger count = 0;
        for (int index = 4; index >= 0; --index) {
            char value = alphabet[(key >> (2 + 6 * index)) & 63];
            if (value) result[count++] = value;
        }
        return [[NSString alloc] initWithBytes:result length:count encoding:NSASCIIStringEncoding];
    }
    NSNumber *unit = strings[@(key)];
    return unit ? fdUnitText(store, unit.unsignedIntegerValue, 512) : nil;
}

typedef struct {
    NSDictionary *bundles;
    NSDictionary *strings;
} FDTables;

static BOOL storeTables(NSData *store, FDTables *tables, NSMutableString *log) {
    const uint8_t *bytes = store.bytes;
    if (store.length < 0x64 || memcmp(bytes, "bdsl\x02", 5) != 0 || !(fd_u32(bytes, 20) & 0x40000000)) {
        [log appendString:@"Header: not a v2 CoreServicesStore.\n"];
        return NO;
    }
    NSDictionary *catalog = fdHashTableEntries(store, 20);
    if (!catalog) { [log appendString:@"Catalog table invalid.\n"]; return NO; }
    tables->bundles = nil;
    tables->strings = nil;
    for (NSNumber *entry in catalog.allValues) {
        NSUInteger unit = entry.unsignedIntegerValue;
        NSString *name = fdUnitText(store, unit, 0x30);
        if ([name isEqualToString:@"Bundle"]) tables->bundles = fdHashTableEntries(store, unit);
        if ([name isEqualToString:@"<string>"]) tables->strings = fdHashTableEntries(store, unit);
    }
    if (!tables->bundles.count || !tables->strings.count) {
        [log appendString:@"Bundle/<string> tables missing.\n"];
        return NO;
    }
    return YES;
}

static NSArray<FDAppRecord *> *parseApps(NSData *store, NSMutableString *log) {
    FDTables tables;
    if (!storeTables(store, &tables, log)) return nil;
    const uint8_t *bytes = store.bytes;
    NSMutableSet *seen = [NSMutableSet set];
    NSMutableArray *apps = [NSMutableArray array];
    NSCountedSet *sizes = [NSCountedSet set];
    for (NSNumber *entry in tables.bundles.allValues) {
        NSUInteger unit = entry.unsignedIntegerValue;
        uint32_t size = fd_u32(bytes, unit + 4);
        [sizes addObject:@(size)];
        const FDLayout *L = layoutForSize(size);
        if (!L) continue;
        NSUInteger body = unit + 8;
        uint32_t key = fd_u32(bytes, body + L->identifier);
        if (fd_u32(bytes, body + L->identifier2) != key || fd_u32(bytes, body + L->kind) != 2) continue;
        NSString *identifier = fdRecordText(store, tables.strings, body, L->identifier);
        if (!identifier.length || [identifier hasSuffix:@".xctrunner"]) continue;
        NSString *bundleName = fdRecordText(store, tables.strings, body, L->bundleName);
        NSString *placeholder = fdRecordText(store, tables.strings, body, L->placeholder);
        NSString *parent = placeholder.stringByDeletingLastPathComponent;
        if (![bundleName hasSuffix:@".app"] ||
            ![placeholder.lastPathComponent isEqualToString:@"SerializedPlaceholder.ipa"] ||
            ![parent.stringByDeletingLastPathComponent isEqualToString:@"/private/var/containers/Bundle/Application"] ||
            ![[NSUUID alloc] initWithUUIDString:parent.lastPathComponent]) continue;
        if ([seen containsObject:identifier]) {
            [log appendFormat:@"Duplicate record for %@; refusing ambiguous store.\n", identifier];
            return nil;
        }
        [seen addObject:identifier];
        NSUInteger offset = body + L->sdk;
        uint64_t sdk[3];
        memcpy(sdk, bytes + offset, sizeof(sdk));
        if (sdk[0] > 99 || sdk[1] > 99 || sdk[2] > 99) {
            [log appendFormat:@"Implausible SDK for %@ (%llu.%llu.%llu); layout mismatch.\n", identifier, sdk[0], sdk[1], sdk[2]];
            return nil;
        }
        NSString *name = fdRecordText(store, tables.strings, body, L->name);
        if (!name.length) name = fdRecordText(store, tables.strings, body, L->name2);
        if (!name.length) name = [bundleName stringByDeletingPathExtension];
        FDAppRecord *app = [FDAppRecord new];
        app.bundleID = identifier;
        app.name = name.length ? name : identifier;
        app.signer = fdRecordText(store, tables.strings, body, L->signer) ?: @"";
        app.containerUUID = parent.lastPathComponent;
        app.bundleName = bundleName;
        app.sdkOffset = offset;
        app.sdkMajor = (NSInteger)sdk[0];
        app.sdkMinor = (NSInteger)sdk[1];
        app.sdkPatch = (NSInteger)sdk[2];
        [apps addObject:app];
    }
    [log appendFormat:@"Bundle units: %lu, record sizes: ", (unsigned long)tables.bundles.count];
    for (NSNumber *size in sizes) [log appendFormat:@"%@×%lu ", size, (unsigned long)[sizes countForObject:size]];
    [log appendFormat:@"\nUser apps parsed: %lu\n", (unsigned long)apps.count];
    return [apps sortedArrayUsingComparator:^NSComparisonResult(FDAppRecord *a, FDAppRecord *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];
}

#pragma mark - CoreServicesStore validation

static BOOL fdStoreOpens(NSString *path, NSError **error) {
    void *handle = dlopen("/System/Library/PrivateFrameworks/CoreServicesStore.framework/CoreServicesStore", RTLD_LAZY | RTLD_LOCAL);
    id (*openStore)(NSURL *, NSError **) = handle ? dlsym(handle, "_CSStoreCreateWithURL") : NULL;
    if (!openStore) return NO;
    id store = openStore([NSURL fileURLWithPath:path], error);
    return store != nil;
}

#pragma mark - File helpers

static NSData *readAll(int fd, NSUInteger maximum) {
    NSMutableData *data = [NSMutableData data];
    char buffer[65536];
    off_t offset = 0;
    ssize_t count;
    while ((count = pread(fd, buffer, sizeof(buffer), offset)) > 0) {
        [data appendBytes:buffer length:(NSUInteger)count];
        offset += count;
        if ((uint64_t)offset > maximum) return nil;
    }
    return count == 0 ? data : nil;
}

static BOOL pwriteAll(int fd, const void *bytes, size_t size, off_t offset) {
    ssize_t result;
    do { result = pwrite(fd, bytes, size, offset); } while (result < 0 && errno == EINTR);
    return result == (ssize_t)size;
}

static BOOL isActiveStoreName(NSString *name) {
    return [name hasPrefix:@"com.apple.LaunchServices-"] && [name hasSuffix:@"-v2.csstore"];
}

static NSString *documentsPath(NSString *sub) {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (sub) path = [path stringByAppendingPathComponent:sub];
    [NSFileManager.defaultManager createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
    return path;
}

#pragma mark - Store discovery

static NSString *lsdContainerCaches(uint64_t kind) {
    void *manager = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!manager) return nil;
    void *(*create)(void) = dlsym(manager, "container_query_create");
    void (*setClass)(void *, uint64_t) = dlsym(manager, "container_query_set_class");
    void (*setIdentifiers)(void *, xpc_object_t) = dlsym(manager, "container_query_set_identifiers");
    void (*setFlags)(void *, uint64_t) = dlsym(manager, "container_query_operation_set_flags");
    void *(*getOne)(void *) = dlsym(manager, "container_query_get_single_result");
    const char *(*getPath)(void *) = dlsym(manager, "container_object_get_path");
    void (*freeQuery)(void *) = dlsym(manager, "container_query_free");
    NSString *path = nil;
    if (create && setClass && setIdentifiers && setFlags && getOne && getPath && freeQuery) {
        void *q = create();
        if (q) {
            setClass(q, kind);
            setIdentifiers(q, xpc_string_create("com.apple.lsd"));
            setFlags(q, 0x100000000ULL); // metadata only, never create
            void *obj = getOne(q);
            const char *raw = obj ? getPath(obj) : NULL;
            if (raw) path = [NSString stringWithUTF8String:raw];
            freeQuery(q);
        }
    }
    dlclose(manager);
    if ([path hasPrefix:@"/var/"]) path = [@"/private" stringByAppendingString:path];
    if (!([path hasPrefix:@"/private/var/containers/Data/System/"] ||
          [path hasPrefix:@"/private/var/mobile/Containers/Data/InternalDaemon/"])) return nil;
    return [path stringByAppendingPathComponent:@"Library/Caches"];
}

static NSArray<NSString *> *inodeScanStoreDirectories(NSMutableString *log) {
    struct statfs volume;
    if (statfs(NSHomeDirectory().fileSystemRepresentation, &volume) != 0) return @[];
    NSMutableOrderedSet *dirs = [NSMutableOrderedSet orderedSet];
    char path[PATH_MAX];
    NSTimeInterval start = NSProcessInfo.processInfo.systemUptime;
    unsigned inode = 16;
    for (; inode <= 40000000; ++inode) {
        if ((inode & 4095) == 0 && NSProcessInfo.processInfo.systemUptime - start > 20.0) break;
        if (fsgetpath(path, sizeof(path), &volume.f_fsid, inode) <= 0) continue;
        if (!strstr(path, "LaunchServices-") || !strstr(path, "-v2.csstore")) continue;
        NSString *match = [NSString stringWithUTF8String:path];
        if ([match hasPrefix:@"/var/"]) match = [@"/private" stringByAppendingString:match];
        if (isActiveStoreName(match.lastPathComponent)) [dirs addObject:match.stringByDeletingLastPathComponent];
    }
    [log appendFormat:@"Inode scan up to %u: %lu directories.\n", inode, (unsigned long)dirs.count];
    return dirs.array;
}

// Directories of csstore files mapped into this process (LaunchServices maps the DB for clients).
static NSArray<NSString *> *mappedStoreDirectories(NSMutableString *log) {
    dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY | RTLD_LOCAL);
    Class proxy = NSClassFromString(@"LSApplicationProxy");
    SEL selector = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if ([proxy respondsToSelector:selector])
        (void)((id (*)(id, SEL, NSString *))objc_msgSend)(proxy, selector, @"com.apple.mobilesafari");
    int (*regionFilename)(int, uint64_t, void *, uint32_t) = dlsym(RTLD_DEFAULT, "proc_regionfilename");
    if (!regionFilename) return @[];
    NSMutableOrderedSet *dirs = [NSMutableOrderedSet orderedSet];
    vm_address_t address = 0;
    for (unsigned i = 0; i < 16384; ++i) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (kr != KERN_SUCCESS || !size || UINTPTR_MAX - address < size) break;
        char buffer[PATH_MAX] = {0};
        if (regionFilename(getpid(), address, buffer, sizeof(buffer)) > 0) {
            NSString *path = [NSString stringWithUTF8String:buffer];
            if ([path hasPrefix:@"/var/"]) path = [@"/private" stringByAppendingString:path];
            if (isActiveStoreName(path.lastPathComponent)) [dirs addObject:path.stringByDeletingLastPathComponent];
        }
        address += size;
    }
    [log appendFormat:@"Mapped csstore directories: %lu\n", (unsigned long)dirs.count];
    return dirs.array;
}

@interface FDAccess : NSObject
@property (nonatomic) int64_t token;
@property (nonatomic) int dir;
@property (nonatomic, copy) NSString *directory;
@property (nonatomic, copy) NSString *storeName;
@end
@implementation FDAccess
- (void)close {
    if (self.dir >= 0) close(self.dir);
    self.dir = -1;
    worse_query_release(self.token);
    self.token = -1;
}
- (NSString *)storePath { return [self.directory stringByAppendingPathComponent:self.storeName]; }
@end

@implementation FDEngine {
    NSMutableString *_log;
    NSString *_storePath;
    NSLock *_lock;
}

+ (FDEngine *)shared {
    static FDEngine *engine;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ engine = [FDEngine new]; });
    return engine;
}

- (instancetype)init {
    if ((self = [super init])) {
        _log = [NSMutableString string];
        _lock = [NSLock new];
    }
    return self;
}

- (NSString *)storePath { return _storePath; }
- (NSString *)lastLog { return [_log copy]; }

+ (NSString *)deviceModel {
    char model[64] = {0};
    size_t size = sizeof(model);
    if (sysctlbyname("hw.machine", model, &size, NULL, 0) != 0) return @"unknown";
    return [NSString stringWithUTF8String:model];
}

// Opens a sandbox extension for one directory and finds the active store in it.
- (FDAccess *)accessDirectory:(NSString *)directory {
    return [self accessDirectory:directory quiet:NO];
}

- (FDAccess *)accessDirectory:(NSString *)directory quiet:(BOOL)quiet {
    int64_t token = worse_query(directory, fdAccessGroup(), false, true);
    if (quiet) {
        if (token < 0) token = worse_query(directory, fdAccessGroup(), true, true);
    } else if (token < 0) {
        int64_t alt = worse_query(directory, fdAccessGroup(), true, true);
        [_log appendFormat:@"  %@ → token %lld / alt %lld\n", directory, token, alt];
        token = alt;
    } else {
        [_log appendFormat:@"  %@ → token %lld\n", directory, token];
    }
    if (token < 0) return nil;
    int dir = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) {
        if (!quiet) [_log appendFormat:@"    open dir errno %d\n", errno];
        worse_query_release(token);
        return nil;
    }
    NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:directory error:nil];
    NSString *best = nil;
    struct timespec bestTime = {0};
    for (NSString *name in names) {
        if (!isActiveStoreName(name)) continue;
        struct stat st;
        if (fstatat(dir, name.fileSystemRepresentation, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode)) continue;
        [_log appendFormat:@"    found %@ (%lld bytes)\n", name, (long long)st.st_size];
        if (!best || st.st_mtimespec.tv_sec > bestTime.tv_sec) {
            best = name;
            bestTime = st.st_mtimespec;
        }
    }
    if (!best) {
        close(dir);
        worse_query_release(token);
        return nil;
    }
    FDAccess *access = [FDAccess new];
    access.token = token;
    access.dir = dir;
    access.directory = directory;
    access.storeName = best;
    return access;
}

- (FDAccess *)openStoreAccess:(NSError **)error {
    NSString *group = fdAccessGroup();
    if (!group) {
        if (error) *error = fdError(@"LiveContainer did not expose a real host App Group. Use a supported LiveContainer installation with App Group access.");
        return nil;
    }
    [_log appendFormat:@"Access group: %@ (%@)\n", group, getenv("LC_HOME_PATH") ? @"LiveContainer" : @"native"];
    NSMutableOrderedSet<NSString *> *candidates = [NSMutableOrderedSet orderedSet];
    NSString *saved = [NSUserDefaults.standardUserDefaults stringForKey:kStoreDirKey];
    if (saved) [candidates addObject:saved];
    for (NSNumber *kind in @[@12, @10]) {
        NSString *path = lsdContainerCaches(kind.unsignedLongLongValue);
        [_log appendFormat:@"lsd container class %@: %@\n", kind, path ?: @"-"];
        if (path) [candidates addObject:path];
    }
    [candidates addObjectsFromArray:@[@"/private/var/containers/Data/System/com.apple.lsd/Library/Caches",
                                       @"/private/var/db/lsd"]];
    for (NSString *directory in candidates) {
        FDAccess *access = [self accessDirectory:directory];
        if (access) return [self rememberAccess:access];
    }
    for (NSString *directory in mappedStoreDirectories(_log)) {
        if ([candidates containsObject:directory]) continue;
        [candidates addObject:directory];
        FDAccess *access = [self accessDirectory:directory];
        if (access) return [self rememberAccess:access];
    }
    for (NSString *root in @[@"/private/var/mobile/Containers/Data/InternalDaemon",
                              @"/private/var/containers/Data/System"]) {
        int64_t token = worse_query(root, fdAccessGroup(), false, true);
        if (token < 0) token = worse_query(root, fdAccessGroup(), true, true);
        NSError *listError = nil;
        NSArray<NSString *> *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:&listError];
        worse_query_release(token);
        [_log appendFormat:@"Root %@: token %lld, %lu entries, error %ld\n", root, token,
            (unsigned long)names.count, (long)listError.code];
        for (NSString *name in names) {
            if (![[NSUUID alloc] initWithUUIDString:name] && ![name hasPrefix:@"com.apple.lsd"]) continue;
            NSString *directory = [[root stringByAppendingPathComponent:name] stringByAppendingPathComponent:@"Library/Caches"];
            if ([candidates containsObject:directory]) continue;
            [candidates addObject:directory];
            FDAccess *access = [self accessDirectory:directory quiet:YES];
            if (access) return [self rememberAccess:access];
        }
    }
    for (NSString *directory in inodeScanStoreDirectories(_log)) {
        if ([candidates containsObject:directory]) continue;
        FDAccess *access = [self accessDirectory:directory];
        if (access) return [self rememberAccess:access];
    }
    if (error) *error = fdError(NSLocalizedString(@"Could not find or open the LaunchServices cache (iOS refused access).", nil));
    return nil;
}

- (FDAccess *)rememberAccess:(FDAccess *)access {
    [NSUserDefaults.standardUserDefaults setObject:access.directory forKey:kStoreDirKey];
    _storePath = access.storePath;
    [_log appendFormat:@"Using store %@\n", _storePath];
    return access;
}

- (NSData *)readStore:(FDAccess *)access stat:(struct stat *)st error:(NSError **)error {
    int fd = openat(access.dir, access.storeName.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (error) *error = fdError([NSString stringWithFormat:NSLocalizedString(@"Could not read the cache (errno %d).", nil), errno]);
        return nil;
    }
    NSData *data = nil;
    if (!fstat(fd, st) && S_ISREG(st->st_mode)) data = readAll(fd, kMaxStore);
    close(fd);
    if (data.length < 0x64 && error) *error = fdError(NSLocalizedString(@"The cache is empty or too large.", nil));
    return data.length >= 0x64 ? data : nil;
}

- (NSArray<FDAppRecord *> *)loadApps:(NSError **)error {
    [_lock lock];
    @try {
        [_log setString:@""];
        [_log appendFormat:@"iOS %@, %@\n", NSProcessInfo.processInfo.operatingSystemVersionString, FDEngine.deviceModel];
        FDAccess *access = [self openStoreAccess:error];
        if (!access) return nil;
        struct stat st;
        NSData *store = [self readStore:access stat:&st error:error];
        BOOL valid = store && fdStoreOpens(access.storePath, NULL);
        [access close];
        if (!store) return nil;
        if (!valid) [_log appendString:@"Warning: CoreServicesStore did not open the live file.\n"];
        NSArray *apps = parseApps(store, _log);
        if (!apps || apps.count < 3) {
            if (error) *error = fdError(NSLocalizedString(@"The cache format does not match a verified layout. Nothing was changed.", nil));
            return nil;
        }
        return apps;
    } @finally {
        [_lock unlock];
    }
}

static BOOL validTriple(NSArray *v) {
    if (![v isKindOfClass:NSArray.class] || v.count != 3) return NO;
    for (NSNumber *n in v) if (![n isKindOfClass:NSNumber.class] || n.integerValue < 0 || n.integerValue > 99) return NO;
    return [v[0] integerValue] >= 1;
}

- (NSString *)applyVersions:(NSDictionary<NSString *, NSArray<NSNumber *> *> *)versions dryRun:(BOOL)dryRun error:(NSError **)error {
    [_lock lock];
    FDAccess *access = nil;
    int fd = -1;
    @try {
        [_log setString:@""];
        access = [self openStoreAccess:error];
        if (!access) return nil;
        struct stat before;
        NSData *original = [self readStore:access stat:&before error:error];
        if (!original) return nil;
        if (!fdStoreOpens(access.storePath, NULL)) {
            if (error) *error = fdError(NSLocalizedString(@"The current cache failed the CoreServicesStore check. Nothing written.", nil));
            return nil;
        }
        NSArray<FDAppRecord *> *apps = parseApps(original, _log);
        if (!apps) {
            if (error) *error = fdError(NSLocalizedString(@"The cache format does not match. Nothing written.", nil));
            return nil;
        }

        // Build candidate in memory: only the 24-byte SDK triple of selected records.
        NSMutableData *candidate = [original mutableCopy];
        NSMutableArray<FDAppRecord *> *changed = [NSMutableArray array];
        NSMutableString *summary = [NSMutableString string];
        for (FDAppRecord *app in apps) {
            NSArray *target = versions[app.bundleID];
            if (!target) continue;
            if (!validTriple(target)) {
                if (error) *error = fdError([NSString stringWithFormat:NSLocalizedString(@"Invalid version for %@.", nil), app.bundleID]);
                return nil;
            }
            uint64_t sdk[3] = {[target[0] unsignedLongLongValue], [target[1] unsignedLongLongValue], [target[2] unsignedLongLongValue]};
            if ((NSInteger)sdk[0] == app.sdkMajor && (NSInteger)sdk[1] == app.sdkMinor && (NSInteger)sdk[2] == app.sdkPatch) continue;
            memcpy((uint8_t *)candidate.mutableBytes + app.sdkOffset, sdk, sizeof(sdk));
            [changed addObject:app];
            [summary appendFormat:@"• %@: %ld.%ld.%ld → %llu.%llu.%llu\n", app.name,
                (long)app.sdkMajor, (long)app.sdkMinor, (long)app.sdkPatch, sdk[0], sdk[1], sdk[2]];
        }
        if (!changed.count) return NSLocalizedString(@"There are no changes to write.", nil);

        // Recompute the store checksum (uint16 at offset 6) via CoreServicesStore.
        NSString *work = documentsPath(@"Work");
        NSString *candidatePath = [work stringByAppendingPathComponent:@"candidate.csstore"];
        if (![candidate writeToFile:candidatePath atomically:YES]) {
            if (error) *error = fdError(NSLocalizedString(@"Could not write the draft copy.", nil));
            return nil;
        }
        NSError *storeError = nil;
        if (!fdStoreOpens(candidatePath, &storeError)) {
            NSNumber *checksum = storeError.userInfo[@"CalculatedChecksum"];
            if (![checksum isKindOfClass:NSNumber.class] || checksum.unsignedLongLongValue > UINT16_MAX) {
                if (error) *error = fdError([NSString stringWithFormat:NSLocalizedString(@"Could not compute the checksum (%@ %ld).", nil), storeError.domain, (long)storeError.code]);
                return nil;
            }
            uint16_t value = checksum.unsignedShortValue;
            memcpy((uint8_t *)candidate.mutableBytes + 6, &value, sizeof(value));
            if (![candidate writeToFile:candidatePath atomically:YES] || !fdStoreOpens(candidatePath, NULL)) {
                if (error) *error = fdError(NSLocalizedString(@"The draft is invalid after the checksum fix. Nothing written.", nil));
                return nil;
            }
        }
        // Verify the candidate's parse yields exactly the requested SDKs and nothing else changed.
        NSMutableIndexSet *allowed = [NSMutableIndexSet indexSetWithIndexesInRange:NSMakeRange(6, 2)];
        for (FDAppRecord *app in changed) [allowed addIndexesInRange:NSMakeRange(app.sdkOffset, 24)];
        const uint8_t *a = original.bytes, *b = candidate.bytes;
        for (NSUInteger i = 0; i < original.length; ++i) {
            if (a[i] != b[i] && ![allowed containsIndex:i]) {
                if (error) *error = fdError(NSLocalizedString(@"The draft changed bytes outside the allowed fields. Nothing written.", nil));
                return nil;
            }
        }
        NSMutableString *scratch = [NSMutableString string];
        NSArray<FDAppRecord *> *reparsed = parseApps(candidate, scratch);
        if (reparsed.count != apps.count) {
            if (error) *error = fdError(NSLocalizedString(@"The draft did not parse back correctly. Nothing written.", nil));
            return nil;
        }

        if (dryRun) {
            fd = openat(access.dir, access.storeName.fileSystemRepresentation, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
            int openErrno = fd < 0 ? errno : 0;
            int lockResult = fd >= 0 ? flock(fd, LOCK_EX | LOCK_NB) : -1;
            if (lockResult == 0) flock(fd, LOCK_UN);
            uint16_t oldSum, newSum;
            memcpy(&oldSum, a + 6, 2);
            memcpy(&newSum, b + 6, 2);
            return [NSString stringWithFormat:@"DRY RUN OK (nothing written). open-for-write errno %d, flock %d, protection %d, checksum %04x→%04x\n%@",
                openErrno, lockResult, fd >= 0 ? fcntl(fd, F_GETPROTECTIONCLASS) : -1, oldSum, newSum, summary];
        }

        // Keep a backup copy of the untouched store.
        NSString *backups = documentsPath(@"Backups");
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"yyyyMMdd-HHmmss";
        NSString *backupName = [NSString stringWithFormat:@"%@-%@", [formatter stringFromDate:NSDate.date], access.storeName];
        [original writeToFile:[backups stringByAppendingPathComponent:backupName] atomically:YES];
        NSArray *old = [[[NSFileManager.defaultManager contentsOfDirectoryAtPath:backups error:nil]
            sortedArrayUsingSelector:@selector(compare:)] mutableCopy];
        for (NSUInteger i = 0; i + 5 < old.count; ++i)
            [NSFileManager.defaultManager removeItemAtPath:[backups stringByAppendingPathComponent:old[i]] error:nil];

        // Write the live store in place.
        fd = openat(access.dir, access.storeName.fileSystemRepresentation, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            if (error) *error = fdError([NSString stringWithFormat:NSLocalizedString(@"iOS did not allow opening the cache for writing (errno %d).", nil), errno]);
            return nil;
        }
        struct stat live;
        if (flock(fd, LOCK_EX | LOCK_NB) != 0 || fstat(fd, &live) || live.st_ino != before.st_ino ||
            live.st_size != (off_t)original.length || ![readAll(fd, kMaxStore) isEqualToData:original]) {
            if (error) *error = fdError(NSLocalizedString(@"lsd just changed or locked the cache. Please try again.", nil));
            return nil;
        }
        BOOL wrote = YES;
        for (FDAppRecord *app in changed)
            wrote = wrote && pwriteAll(fd, b + app.sdkOffset, 24, (off_t)app.sdkOffset);
        wrote = wrote && pwriteAll(fd, b + 6, 2, 6) && fsync(fd) == 0;
        NSData *after = readAll(fd, kMaxStore);
        BOOL verified = wrote && [after isEqualToData:candidate] && fdStoreOpens(access.storePath, NULL);
        if (!verified) {
            BOOL restored = YES;
            for (FDAppRecord *app in changed)
                restored = restored && pwriteAll(fd, a + app.sdkOffset, 24, (off_t)app.sdkOffset);
            restored = restored && pwriteAll(fd, a + 6, 2, 6) && fsync(fd) == 0 &&
                [readAll(fd, kMaxStore) isEqualToData:original];
            if (error) *error = fdError(restored ? NSLocalizedString(@"The write could not be verified; the original bytes were restored.", nil) :
                NSLocalizedString(@"The write failed and could not be restored. A backup is in Documents/Backups.", nil));
            return nil;
        }
        [_log appendFormat:@"Applied %lu records, inode %llu.\n", (unsigned long)changed.count, (unsigned long long)live.st_ino];
        return [NSString stringWithFormat:NSLocalizedString(@"Wrote and verified %lu app(s):\n%@", nil), (unsigned long)changed.count, summary];
    } @finally {
        if (fd >= 0) close(fd);
        [access close];
        [_lock unlock];
    }
}

- (NSString *)exportDiagnostics:(NSError **)error {
    [_lock lock];
    @try {
        [_log setString:@""];
        [_log appendFormat:@"iOS %@, %@\n", NSProcessInfo.processInfo.operatingSystemVersionString, FDEngine.deviceModel];
        FDAccess *access = [self openStoreAccess:error];
        if (!access) {
            NSString *folder = documentsPath(@"Diagnostics");
            [_log writeToFile:[folder stringByAppendingPathComponent:@"report.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
            return nil;
        }
        struct stat st;
        NSData *store = [self readStore:access stat:&st error:error];
        NSError *openError = nil;
        BOOL valid = store && fdStoreOpens(access.storePath, &openError);
        [access close];
        [_log appendFormat:@"Store %@: %lu bytes, inode %llu, mode %o, uid %u, CSStore valid %d (%@ %ld)\n",
            access.storeName, (unsigned long)store.length, (unsigned long long)st.st_ino, st.st_mode, st.st_uid,
            valid, openError.domain, (long)openError.code];
        NSString *folder = documentsPath(@"Diagnostics");
        if (store) [store writeToFile:[folder stringByAppendingPathComponent:@"store.csstore"] atomically:YES];
        NSArray<FDAppRecord *> *apps = store ? parseApps(store, _log) : nil;
        for (FDAppRecord *app in apps)
            [_log appendFormat:@"%@\t%@\t%ld.%ld.%ld\t%@\t0x%lx\n", app.bundleID, app.name,
                (long)app.sdkMajor, (long)app.sdkMinor, (long)app.sdkPatch, app.signer, (unsigned long)app.sdkOffset];
        [_log writeToFile:[folder stringByAppendingPathComponent:@"report.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
        return [_log copy];
    } @finally {
        [_lock unlock];
    }
}

@end
