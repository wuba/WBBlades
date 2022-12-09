//
//  ASUtils.h
//  WBAppSize
//
//  Created by Shwnfee on 2022/11/2.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

@interface ASUtils : NSObject

+ (NSString *)fileNameStripSubfix:(NSString *)fileName;

+ (NSString *)typeInPath:(NSString *)path;

+ (NSUInteger)bytesSizeForFile:(NSString *)path;

+ (NSString*)discriptionWithByteSize:(NSUInteger)size;

+ (NSURL *)cachePathURL;

+ (NSDictionary *)obtainNibInfoForNibPath:(NSString *)nibPath;

+ (NSArray *)customUsingNameForFileName:(NSString *)fileName;

@end

