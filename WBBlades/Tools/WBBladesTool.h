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

/**
 * Return an array contains continuous strings from the file data.
 * See method implementation for details.
 */
+ (NSArray *)readStrings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

/**
 * Return a single string from the file data.
 * @param range Indicate the start location of the buffer storing the string.
 * @param len The actural size of the buffer.
 * @param fileData The file data to be read from.
 * @return The string in the file data start at the end of the range whose size is len.
 */
+ (NSString *)readString:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

/**
 * Return bytes data from the file data.
 */
+ (NSData *)readBytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData;

/**
 * Replace the escape characters in the input string.
 */
+ (NSString *)replaceEscapeCharsInString:(NSString *)orig;

/**
 * disassembly
 */
+ (cs_insn *)disassemWithMachOFile:(NSData *)fileData  from:(unsigned long long)begin length:(unsigned long long )size;

@end

NS_ASSUME_NONNULL_END
