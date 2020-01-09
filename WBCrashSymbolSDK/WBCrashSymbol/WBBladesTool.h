//
//  WBBladesTool.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesTool : NSObject

+ (NSArray *)read_strings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

+ (NSString *)read_string:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

+ (NSData *)read_bytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData;

+ (NSString *) replaceEscapeCharsInString: (NSString *)orig;

@end

NS_ASSUME_NONNULL_END
