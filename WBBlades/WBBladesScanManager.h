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



#define NSSTRING(C_STR) [NSString stringWithCString: (char *)(C_STR) encoding: [NSString defaultCStringEncoding]]
#define CSTRING(NS_STR) [(NS_STR) cStringUsingEncoding: [NSString defaultCStringEncoding]]

struct class64 {
    unsigned long long isa;
    unsigned long long superClass;
    unsigned long long cache;
    unsigned long long vtable;
    unsigned long long data;
    
};

struct cfstring64 {
    unsigned long long ptr;
    unsigned long long unknown;
    unsigned long long stringAddress;
    unsigned long long size;
    
};

struct class64Info {
    unsigned int flags;
    unsigned int instanceStart;
    unsigned int instanceSize;
    unsigned int reserved;
    unsigned long long  instanceVarLayout;
    unsigned long long  name;
    unsigned long long  baseMethods;
    unsigned long long  baseProtocols;
    unsigned long long  instanceVariables;
    unsigned long long  weakInstanceVariables;
    unsigned long long  baseProperties;
};

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
