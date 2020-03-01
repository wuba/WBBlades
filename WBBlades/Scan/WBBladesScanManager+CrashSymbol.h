//
//  WBBladesScanManager+CrashSymbol.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (CrashSymbol)

/*
 * 将指定的偏移地址符号化
 * fileData:可执行文件
 * crashOffsets:崩溃日志中待符号化的偏移地址，多个地址按逗号分隔 @"address0,address1..."
 */
+ (NSDictionary *)symbolizeWithMachOFile:(NSData *)fileData crashOffsets:(NSString *)crashAddress;

@end

NS_ASSUME_NONNULL_END
