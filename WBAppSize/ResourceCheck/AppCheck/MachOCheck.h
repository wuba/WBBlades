//
//  MachOCheck.h
//  AppSizeManager
//
//  Created by wbblades on 2022/3/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


@interface MachOCheck : NSObject

+ (CGFloat)checkTEXTHasMigratedSize:(NSString *)libPath;
+ (NSDictionary*)checkHasStripedFrameworks:(NSString *)appPath;
+ (NSArray *)scanUnusedClassesInFile:(NSString *)appPath;
+ (void)copyFileFromPath:(NSString *)from toPath:(NSString *)to;
+ (NSString *)storeOptimizePath;
+ (void)cleanCompressImageRootPath;
/**
 预处理下APP的可执行文件
 */
+ (void)preHandleMainBinary:(NSString *)filePath;

@end

NS_ASSUME_NONNULL_END
