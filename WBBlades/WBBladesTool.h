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

+ (NSArray *)readStrings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

+ (NSString *)readString:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

+ (NSData *)readBytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData;

+ (NSString *) replaceEscapeCharsInString: (NSString *)orig;

+ (cs_insn * )scanAllASMWithfileData:(NSData *)fileData  begin:(unsigned long long)begin size:(unsigned long long )size;

@end

NS_ASSUME_NONNULL_END
