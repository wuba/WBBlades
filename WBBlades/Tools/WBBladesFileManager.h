//
//  WBBladesFileManager.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesFileManager : NSObject

/** Get data from the file. */
+ (NSData *)readFromFile:(NSString *)filePath;

/**
 * Get the binary file. If it is an app, read the binary file directly and do the architecture split.
 * @return The arm64 architecture.
 */
+ (NSData *)readArm64FromFile:(NSString *)filePath;

/*
 * 将指定的偏移地址符号化
 * crashLogPath:崩溃日志原文件路径
 * appPath:可执行文件路径
 */
+ (NSArray *)obtainAllCrashOffsets:(NSString *)crashLogPath appPath:(NSString *)appPath;

/*
 * 将指定的偏移地址符号化
 * result:结果数据
 */
+ (NSString *)obtainOutputLogWithResult:(NSDictionary *)result;
@end

NS_ASSUME_NONNULL_END
