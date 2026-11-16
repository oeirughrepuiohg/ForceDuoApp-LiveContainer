#import "FDSandbox.h"
#import "worse_query.h"
#include <dlfcn.h>
#include <xpc/xpc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static NSString *const kDefaultGroup = @"group.com.34306.forceDuo";
static NSMutableString *gDiag;
NSString *FDLastGrantDiagnostic(void) { return gDiag ? [gDiag copy] : @""; }
#define DIAG(...) do { if (!gDiag) gDiag = [NSMutableString string]; [gDiag appendFormat:__VA_ARGS__]; } while (0)

#pragma mark - Entitlements

static id copyEntitlement(NSString *key) {
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    if (!security) return nil;
    typedef void *(*create_fn)(CFAllocatorRef);
    typedef CFTypeRef (*copy_fn)(void *, CFStringRef, CFErrorRef *);
    create_fn createTask = (create_fn)dlsym(security, "SecTaskCreateFromSelf");
    copy_fn copyValue = (copy_fn)dlsym(security, "SecTaskCopyValueForEntitlement");
    id value = nil;
    if (createTask && copyValue) {
        void *task = createTask(kCFAllocatorDefault);
        if (task) {
            CFTypeRef raw = copyValue(task, (__bridge CFStringRef)key, NULL);
            value = CFBridgingRelease(raw);
            CFRelease(task);
        }
    }
    dlclose(security);
    return value;
}

NSArray<NSString *> *FDEntitledAppGroups(void) {
    id value = copyEntitlement(@"com.apple.security.application-groups");
    NSMutableArray *groups = [NSMutableArray array];
    if ([value isKindOfClass:NSString.class]) [groups addObject:value];
    if ([value isKindOfClass:NSArray.class])
        for (id item in value) if ([item isKindOfClass:NSString.class]) [groups addObject:item];
    return groups;
}

NSString *FDResolvedAppGroup(void) {
    static NSString *resolved;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if ([NSProcessInfo.processInfo.arguments containsObject:@"--fd-nogroup"]) return; // test the fallback
        NSMutableArray<NSString *> *ordered = [NSMutableArray array];
        NSArray<NSString *> *entitled = FDEntitledAppGroups();
        // Prefer our own group (possibly renamed by the signer), then anything else entitled.
        for (NSString *g in entitled)
            if ([g rangeOfString:@"forceDuo" options:NSCaseInsensitiveSearch].location != NSNotFound) [ordered addObject:g];
        for (NSString *g in entitled) if (![ordered containsObject:g]) [ordered addObject:g];
        if (![ordered containsObject:kDefaultGroup]) [ordered addObject:kDefaultGroup];
        NSFileManager *files = NSFileManager.defaultManager;
        for (NSString *g in ordered) {
            if ([files containerURLForSecurityApplicationGroupIdentifier:g]) { resolved = g; break; }
        }
    });
    return resolved;
}

#pragma mark - Public

// Only a sandbox denial (EPERM) means the token did not help; EACCES is ordinary
// file permissions, which a token never changes.
static BOOL grantOpens(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) { close(fd); return YES; }
    return errno != EPERM;
}

static NSString *describe(int64_t code) {
    switch (code) {
        case -1: return @"consume failed";        // group resolved, so -1 comes from sandbox_extension_consume
        case -2: return @"API missing";
        case -3: return @"query create failed";
        case -4: return @"symlink failed";
        case -5: return @"query rejected";
        case -6: return @"no token";
        case -8: return @"token does not open target";
        case -255: return @"target missing";
        default: return [NSString stringWithFormat:@"%lld", code];
    }
}

// One query: the token must be issued, consumed, and actually open the target.
static int64_t tryGrant(NSString *path, NSString *group, BOOL alt) {
    int64_t handle = worse_query(path, group, alt, false);
    if (handle >= 0 && !grantOpens(path)) {
        worse_query_release(handle);
        handle = -8;
    }
    return handle;
}

int64_t FDGrantAccess(NSString *path, NSString **method) {
    NSString *group = FDResolvedAppGroup();
    if (!group) {
        DIAG(@"no usable App Group (entitled: %@)\n", [FDEntitledAppGroups() componentsJoinedByString:@", "]);
        if (method) *method = @"no-app-group";
        return -1;
    }
    // worse_query needs an existing target; a dangling Caches link only wastes a query.
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0 && errno == ENOENT) {
        if (method) *method = describe(-255);
        return -255;
    }
    // The flag set that works is remembered for the run (iOS 27 usually wants the standard set).
    static int preferAlt = -1;
    static NSString *preferGroup;
    NSMutableArray<NSString *> *groups = [NSMutableArray arrayWithObject:preferGroup ?: group];
    NSFileManager *files = NSFileManager.defaultManager;
    for (NSString *g in FDEntitledAppGroups())
        if (![groups containsObject:g] && [files containerURLForSecurityApplicationGroupIdentifier:g]) [groups addObject:g];

    NSMutableArray<NSString *> *attempts = [NSMutableArray array];
    BOOL altFirst = preferAlt >= 0 ? (BOOL)preferAlt : NO;
    for (NSString *g in groups) {
        for (int pass = 0; pass < 2; ++pass) {
            BOOL alt = pass == 0 ? altFirst : !altFirst;
            int64_t handle = tryGrant(path, g, alt);
            if (handle >= 0) {
                preferAlt = alt;
                preferGroup = g;
                if (method) *method = [NSString stringWithFormat:@"%@%@%@", alt ? @"alt flags" : @"std flags",
                                       attempts.count ? @" after " : @"", [attempts componentsJoinedByString:@", "]];
                return handle;
            }
            [attempts addObject:[NSString stringWithFormat:@"%@ %@: %@", g == group ? @"group" : g,
                                 alt ? @"alt" : @"std", describe(handle)]];
            if (handle == -2) break;
        }
        if (attempts.count >= 6) break;  // a few groups are plenty; every query swaps Caches
    }
    if (method) *method = [attempts componentsJoinedByString:@"; "];
    DIAG(@"worse_query %@ failed: %@\n", path, [attempts componentsJoinedByString:@"; "]);
    return -1;
}
