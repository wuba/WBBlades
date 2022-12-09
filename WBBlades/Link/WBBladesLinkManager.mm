//
//  WBBladesLinkManager.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesLinkManager.h"
#import <mach-o/nlist.h>

#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"

#define SYMBOL_TABLE @"symbol_tab"
#define STRING_TABLE @"string_tab"

//extern unsigned long symSize;
//extern unsigned long stringSize;

typedef struct wb_objc_classdata {
    long long flags;
    long long instanceStart;
    long long instanceSize;
    long long reserved;
    unsigned long long ivarlayout;
    unsigned long long name;
    unsigned long long baseMethod;
    unsigned long long baseProtocol;
    unsigned long long ivars;
    unsigned long long weakIvarLayout;
    unsigned long long baseProperties;
} wb_objc_classdata;

@interface WBBladesLinkManager ()

@property (nonatomic, strong) NSMutableDictionary<NSString *,NSMutableSet*> *unixData;

@property (nonatomic, assign) unsigned long long linkSize;

@property (nonatomic, strong) NSMutableSet *abandonStringSet;

@end

@implementation WBBladesLinkManager

+ (WBBladesLinkManager *)shareInstance {
    static WBBladesLinkManager* linker = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        linker = [[WBBladesLinkManager alloc] init];
        linker.unixData = [NSMutableDictionary dictionary];
        linker.abandonStringSet = [NSMutableSet set];
    });
    return linker;
}

- (unsigned long long)linkWithObjects:(NSArray<WBBladesObject *>*)objects {
    self.linkSize = 0;
    self.unixData = [NSMutableDictionary dictionary];
    for (WBBladesObject *object in objects) {
        self.linkSize += object.objectMachO.size;

        // 对section进行链接
        [object.objectMachO.sections enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSArray * _Nonnull section, BOOL * _Nonnull stop) {
            if (!self.unixData[key]) {
                self.unixData[key] = [NSMutableSet set];
            }

            NSMutableSet *set = self.unixData[key];
            for (id value in section) {
                int scale = [key isEqualToString:@"(__TEXT,__ustring)"] ? 2 : 1;
                if ([set containsObject:value]) {
                    self.linkSize -= [value length] * scale;
                }
                [set addObject:value];
            }
        }];
    }
    return self.linkSize;
}

- (void)clearLinker {
    self.unixData = nil;
    self.unixData = [NSMutableDictionary dictionary];
    self.linkSize = 0;
    self.abandonStringSet = nil;
    self.abandonStringSet = [NSMutableSet set];
}

@end
