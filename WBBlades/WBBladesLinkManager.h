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

- (unsigned long long )linkWithObjects:(NSArray<WBBladesObject *>*)objects;

- (void)clearLinker;

@end

NS_ASSUME_NONNULL_END
