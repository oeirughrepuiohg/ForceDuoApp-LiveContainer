#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// The App Group this build was actually signed with.
/// Sideloadly / AltStore / SideStore rewrite group IDs (for example
/// `group.com.34306.forceDuo.<TEAMID>`), so the ID is read from the
/// process's own `com.apple.security.application-groups` entitlement
/// instead of being hardcoded. LiveContainer uses its real host group.
/// Returns nil when no usable group is present.
NSString *_Nullable FDResolvedAppGroup(void);

/// Every App Group in this process's entitlements (may be empty).
NSArray<NSString *> *FDEntitledAppGroups(void);

/// Opens a sandbox extension for `path` with worse_query through the resolved
/// App Group (both flag sets). Returns a handle >= 0 on success; release it with worse_query_release().
int64_t FDGrantAccess(NSString *path, NSString *_Nullable *_Nullable method);

NSString *FDLastGrantDiagnostic(void);

NS_ASSUME_NONNULL_END
