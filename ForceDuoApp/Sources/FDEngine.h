#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const FDAppGroup;
extern NSErrorDomain const FDErrorDomain;

@interface FDAppRecord : NSObject
@property (nonatomic, copy) NSString *bundleID;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *signer;
@property (nonatomic, copy) NSString *containerUUID;
@property (nonatomic, copy) NSString *bundleName;
@property (nonatomic) NSUInteger sdkOffset;
@property (nonatomic) NSInteger sdkMajor;
@property (nonatomic) NSInteger sdkMinor;
@property (nonatomic) NSInteger sdkPatch;
@property (nonatomic, readonly) BOOL storeSigned;
@end

@interface FDEngine : NSObject
@property (class, nonatomic, readonly) FDEngine *shared;
@property (nonatomic, readonly, nullable) NSString *storePath;
@property (nonatomic, readonly) NSString *lastLog;

/// Grants access to the lsd cache with worse_query, reads and parses every user app.
- (nullable NSArray<FDAppRecord *> *)loadApps:(NSError **)error;

/// bundleID -> @[major, minor, patch]. Writes only the SDK fields of those records
/// (and the store checksum), verifies the result, and returns a human-readable summary.
- (nullable NSString *)applyVersions:(NSDictionary<NSString *, NSArray<NSNumber *> *> *)versions
                              dryRun:(BOOL)dryRun
                               error:(NSError **)error;

/// Read-only: copies the active store into Documents/Diagnostics with a layout report.
- (nullable NSString *)exportDiagnostics:(NSError **)error;

+ (NSString *)deviceModel;
@end

NS_ASSUME_NONNULL_END
