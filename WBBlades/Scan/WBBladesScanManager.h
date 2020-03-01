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

/**
 *  scan static library size
 *  @param fileData - binary data
 */
+ (unsigned long long)scanStaticLibrary:(NSData *)fileData;

/**
*  scan symbol table header and return model
*  @param fileData binary data
*  @param range range
*/
+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range;

/**
*  scan symbol table and return model
*  @param fileData binary data
*  @param range range
*/
+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range;

/**
*  scan string table and return model
*  @param fileData binary data
*  @param range range
*/
+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range;

/**
*  scan object file and return model
*  @param fileData binary data
*  @param range range
*/
+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange)range;

/**
*  use eight-bytes alignment
*  @param range range
*/
+ (NSRange)rangeAlign:(NSRange)range;

/**
*  judge whether the file is supported
*  @param fileData binary data
*/
+ (BOOL)isSupport:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
