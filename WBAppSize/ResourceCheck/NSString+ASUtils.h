//
//  NSString+ASUtils.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSString (ASUtils)
- (NSString *)as_sha256Value;
+ (NSString *)as_getFileSHA256StrFromPath:(NSString *)path;
@end

NS_ASSUME_NONNULL_END
