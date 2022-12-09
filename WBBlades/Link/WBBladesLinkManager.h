//
//  WBBladesLinkManager.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class WBBladesObject;
@interface WBBladesLinkManager : NSObject

/**
 * Get the instance.
 * @return The Singleton.
 */
+ (WBBladesLinkManager *)shareInstance;

/**
 * Integrate all target objects and return the linked size.
 */
- (unsigned long long)linkWithObjects:(NSArray<WBBladesObject *>*)objects;

/**
 * Clear the link manager share instance.
 */
- (void)clearLinker;

@end

NS_ASSUME_NONNULL_END
