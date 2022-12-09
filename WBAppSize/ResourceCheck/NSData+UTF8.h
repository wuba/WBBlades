//
//  NSData+UTF8.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

@interface NSData (UTF8)
- (NSString *)UTF8ReplacementStr;
- (NSData *)UTF8Data;
@end
