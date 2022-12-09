//
//  WBBladesScanManager+CrashSymbol.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/12/30.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesScanManager.h"
#import "WBBladesDefines.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (CrashSymbol)

/*
 * 将指定的偏移地址符号化
 * fileData:可执行文件
 * crashOffsets:崩溃日志中待符号化的偏移地址，多个地址 @[address0,address1...]
 */
+ (NSDictionary *)symbolizeWithMachOFile:(NSData *)fileData crashOffsets:(NSArray *)crashAddress;
+ (NSString *)swiftClassMethod:(struct SwiftMethod)method memberOffset:(uintptr_t)memberOffset member:(struct FieldRecord)member vm:(uintptr_t)vm squ:(NSInteger)squ memSqu:(NSInteger)memSqu fileData:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
