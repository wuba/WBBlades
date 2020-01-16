//
//  WBBladesScanManager+UnuseClassScan.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/8/5.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (UnuseClassScan)

/*
 * 在指定文件中扫描指定的目标类集合。
 * fileData：二进制文件
 * aimClasses：在二进制的哪些类中查找无用类
 */
+ (NSSet *)scanAllClassWithFileData:(NSData*)fileData classes:(NSSet *)aimClasses;

//dump 二进制中的所有类
+ (NSSet*)dumpClassList:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
