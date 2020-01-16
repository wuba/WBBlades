//
//  WBBladesTool.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "capstone.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesTool : NSObject

//读取连续字符串
+ (NSArray *)readStrings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

//读取单个字符串
+ (NSString *)readString:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

//读取字节
+ (NSData *)readBytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData;

//字符替换
+ (NSString *)replaceEscapeCharsInString: (NSString *)orig;

//反汇编
+ (cs_insn *)disassemWithMachOFile:(NSData *)fileData  from:(unsigned long long)begin length:(unsigned long long )size;

@end

NS_ASSUME_NONNULL_END
