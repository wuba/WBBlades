//
//  WBBladesScanManager.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"
NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager : NSObject

//扫描静态库
+ (unsigned long long)scanStaticLibrary:(NSData *)fileData;

//检测文件是否支持分析
+ (BOOL)isSupport:(NSData *)fileData;

//扫描符号表头
+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range;

//扫描符号表
+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range;

//扫描字符串表
+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range;

//扫描目标文件
+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange)range;

//字节对齐（8字节）
+ (NSRange)rangeAlign:(NSRange)range;

@end

NS_ASSUME_NONNULL_END
