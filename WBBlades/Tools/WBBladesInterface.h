//
//  WBBladesHelper.h
//  WBBlades
//
//  Created by 竹林七闲 on 2022/4/11.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
extern  NSString *resultFilePath(void);
@interface WBBladesInterface : NSObject
@property(nonatomic, strong, nullable)NSString *libarySizeInfos;
@property(nonatomic, strong, nullable)NSString *unusedClassInfos;
@property(nonatomic, strong, nullable)NSString *autoHookInfos;
@property(nonatomic, assign)BOOL autoHookFinished;
+ (WBBladesInterface *)shareInstance;
+ (void)handleStaticLibrary:(NSString *)filePath;
+ (void)scanStaticLibraryByInputPath:(NSString *)inputPath;
+ (void)scanUnusedClassByInputPaths: (NSArray<NSString *>*)inputPath;
+ (void)autoHookByInputPaths:(NSString *)filePath;
+ (void)endAutoHookProcess;
+ (NSArray<NSDictionary<NSString *, NSNumber *> *> *)scanUnusedClassWithAppPath:(NSString *)appFilePath fromLibs:(NSArray<NSString *> *)fromLibsPath;
+ (NSString *)scanCrashSymbolByCrashLogPath:(NSString *)crashLogPath executableAppPath:(NSString *)appPath;
+ (NSString *)scanDependLibs:(NSString *)folderPath;
@end

NS_ASSUME_NONNULL_END
