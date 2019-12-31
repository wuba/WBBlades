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

+ (unsigned long long)scanStaticLibrary:(NSData *)fileData;

+ (void)scanSymbolTabWithFileData:(NSData *)fileData;

+ (BOOL)isSupport:(NSData *)fileData;

+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range;

+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range;

+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range;

+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange)range;

+ (NSRange)rangeAlign:(NSRange)range;

@end

NS_ASSUME_NONNULL_END
