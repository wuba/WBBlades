//
//  WBBladesObject.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WBBladesObjectHeader.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesObjectMachO : NSObject

@property (nonatomic, assign) NSRange range;

@property (nonatomic, assign) unsigned long long size;

@property (nonatomic, assign) char *stringTab;

@property (nonatomic, assign) unsigned long long stringSize;

@property (nonatomic, strong) NSArray<NSNumber*> *symbolTab;//只保存在字符表的索引，地址不记录

@property (nonatomic, strong) NSMutableSet *undefinedSymbols;

@property (nonatomic, strong) NSMutableSet *definedSymbols;

@property (nonatomic, strong) NSMutableDictionary< NSString*,NSArray *> *sections; //存放__TEXT且为常量的文本段

@end

@interface WBBladesObject : NSObject

@property (nonatomic, strong) WBBladesObjectHeader *objectHeader;

@property (nonatomic, strong) WBBladesObjectMachO *objectMachO;

@property (nonatomic, assign) NSRange range;

@end


@interface WBBladesHelper : NSObject

@property (nonatomic, copy) NSString *className;

@property (nonatomic, assign) unsigned long long offset;

@end


NS_ASSUME_NONNULL_END
