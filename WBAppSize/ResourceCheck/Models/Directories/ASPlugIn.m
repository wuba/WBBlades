//
//  ASPlugIn.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASPlugIn.h"
#import "ASFileManager.h"
@implementation ASPlugIn

+ (void)load{
    [[ASFileManager shareInstance] registerDirectoryModelClassString:NSStringFromClass([ASPlugIn class]) withDirectoryType:@"appex"];
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath{
    if (self = [super initWithDirectoryPath:directoryPath]) {
        if (self.current.machOFiles.count>0) {
            self.exeFile = [self.current.machOFiles firstObject];
        }
    }
    return self;
}

@end
