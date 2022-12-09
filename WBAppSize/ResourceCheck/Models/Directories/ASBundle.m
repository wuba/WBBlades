//
//  ASBundle.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBundle.h"
#import "ASFileManager.h"

@implementation ASBundle
+ (void)load{
    [[ASFileManager shareInstance] registerDirectoryModelClassString:NSStringFromClass([ASBundle class]) withDirectoryType:@"bundle"];
}

@end
