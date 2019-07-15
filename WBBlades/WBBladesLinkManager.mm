//
//  WBBladesLinkManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/15.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesLinkManager.h"
#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"
#import <mach-o/nlist.h>

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

@property(nonatomic,strong) NSMutableDictionary<NSString *,NSMutableSet*> *unixData;

@property(nonatomic,assign)unsigned long long linkSize;

@property(nonatomic,strong) NSMutableSet *abandonStringSet;

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

- (unsigned long long )linkWithObjects:(NSArray<WBBladesObject *>*)objects{
    for (WBBladesObject *object in objects) {
        
        self.linkSize += object.objectMachO.size;
        
        //对section 进行链接
        [object.objectMachO.sections enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSArray * _Nonnull section, BOOL * _Nonnull stop) {
            
            if (!self.unixData[key]) {
                self.unixData[key] = [NSMutableSet set];
            }
            
            NSMutableSet *set = self.unixData[key];
            
            for (id value in section) {
                
                int scale = [key isEqualToString:@"(__TEXT,__ustring)"]?2:1;
                if ([set containsObject:value]) {
                    self.linkSize -= [value length] * scale;
                }
                [set addObject:value];
            }
        }];
        
//        //对符号表进行链接
//        if (!self.unixData[SYMBOL_TABLE]) {
//            self.unixData[SYMBOL_TABLE] = [NSMutableSet set];
//        }
//        NSMutableSet *symbolSet = self.unixData[SYMBOL_TABLE];
//        for (NSDictionary  *indexDic in object.objectMachO.symbolTab) {
//            unsigned long index = [indexDic[@"index"] unsignedIntegerValue];
//            unsigned char type = [indexDic[@"type"] charValue];
//            char *symbol = object.objectMachO.stringTab + index;
//            NSString *symbolName = [NSString stringWithUTF8String:symbol];
//
//            if (type == 0x0e) {
//                self.linkSize -= sizeof(nlist_64);
//                self.linkSize -= (symbolName.length + 1);
//                [self.abandonStringSet addObject:symbolName];
//
////                symSize -= sizeof(nlist_64);
////                stringSize -= (symbolName.length + 1);
//            }else{
//                if ([symbolSet containsObject:symbolName]) {
//                    self.linkSize -= sizeof(nlist_64);
////                    symSize -= sizeof(nlist_64);
//                }
//                [symbolSet addObject:symbolName];
//            }
//        }
//
//        //对字符串表进行链接
//        if (!self.unixData[STRING_TABLE]) {
//            self.unixData[STRING_TABLE] = [NSMutableSet set];
//        }
//        NSMutableSet *stringSet = self.unixData[STRING_TABLE];
//        char * strP = object.objectMachO.stringTab;
//        while (strP < object.objectMachO.stringSize + object.objectMachO.stringTab) {
//            NSString *string = [NSString stringWithUTF8String:strP];
//            if ([stringSet containsObject:string] && ![stringSet containsObject:string]) {
//                self.linkSize -= ([string length] + 1);
////                stringSize -= ([string length] + 1);
//            }
//            [stringSet addObject:string];
//            strP += [string length] + 1;
//        }
    }
    
    return self.linkSize;
}

- (void)clearLinker{
    self.unixData = nil;
    self.unixData = [NSMutableDictionary dictionary];
    self.linkSize = 0;
    self.abandonStringSet = nil;
    self.abandonStringSet = [NSMutableSet set];
}


@end
