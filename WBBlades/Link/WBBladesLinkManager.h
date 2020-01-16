//
//  WBBladesLinkManager.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/15.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class WBBladesObject;
@interface WBBladesLinkManager : NSObject

+ (WBBladesLinkManager *)shareInstance;

//整合所有的目标文件
- (unsigned long long )linkWithObjects:(NSArray<WBBladesObject *>*)objects;

//清除目标文件
- (void)clearLinker;

@end

NS_ASSUME_NONNULL_END
