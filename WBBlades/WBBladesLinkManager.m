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

@interface WBBladesLinkManager ()

@property(nonatomic,strong) NSMutableDictionary<NSString *,NSMutableSet*> *unixData;

@property(nonatomic,assign)unsigned long long linkSize;

@end

@implementation WBBladesLinkManager

+ (WBBladesLinkManager *)shareInstance {
    static WBBladesLinkManager* linker = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        linker = [[WBBladesLinkManager alloc] init];
        linker.unixData = [NSMutableDictionary dictionary];
    });
    return linker;
}

- (unsigned long long )linkWithObjects:(NSArray<WBBladesObject *>*)objects{

    for (WBBladesObject *object in objects) {
        
        self.linkSize += object.objectMachO.size;
        [object.objectMachO.sections enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSArray * _Nonnull section, BOOL * _Nonnull stop) {
            
            if (!self.unixData[key]) {
                self.unixData[key] = [NSMutableSet set];
            }
            
            NSMutableSet *set = self.unixData[key];

            for (id value in section) {
                if ([set containsObject:value]) {
                    self.linkSize -= [value length];
                }
                [set addObject:value];
            }
        }];
    }
    return self.linkSize;
}

- (void)clearLinker{
    self.unixData = nil;
    self.unixData = [NSMutableDictionary dictionary];
}


@end
