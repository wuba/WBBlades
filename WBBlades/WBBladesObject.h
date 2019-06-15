//
//  WBBladesObject.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/15.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WBBladesObjectHeader.h"
NS_ASSUME_NONNULL_BEGIN

@interface WBBladesObjectMachO : NSObject

@property(nonatomic,assign)NSRange range;

@property(nonatomic,assign)unsigned long long size;

@property(nonatomic,strong)NSMutableDictionary< NSString*,NSArray *> *sections; //存放__TEXT且为常量的文本段

@end

@interface WBBladesObject : NSObject

@property(nonatomic,strong)WBBladesObjectHeader *objectHeader;

@property(nonatomic,strong)WBBladesObjectMachO *objectMachO;

@property(nonatomic,assign)NSRange range;

@end

NS_ASSUME_NONNULL_END
