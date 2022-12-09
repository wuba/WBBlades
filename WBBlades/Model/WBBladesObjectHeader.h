//
//  WBBladesObjectHeader.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

/**
 对应Mach-O中的Object Header段信息
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesObjectHeader : NSObject

@property (nonatomic, copy) NSString *name;

@property (nonatomic, copy) NSString *timeStamp;

@property (nonatomic, copy) NSString *userID;

@property (nonatomic, copy) NSString *groupID;

@property (nonatomic, copy) NSString *mode;

@property (nonatomic, copy) NSString *size;

@property (nonatomic, copy) NSString *endHeader;

@property (nonatomic, copy) NSString *longName;

@property (nonatomic, assign) NSRange range;

@end

NS_ASSUME_NONNULL_END
