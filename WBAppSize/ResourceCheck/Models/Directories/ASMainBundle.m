//
//  ASMainBundle.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASMainBundle.h"
#import "ASImageFile.h"
#import "ASCarFile.h"
#import "ASFramework.h"
#import "ASPlugIn.h"
#import "ASFileManager.h"
#import "ASNibFile.h"
#import "ASNibDirectory.h"

@implementation ASMainBundle

+ (void)load{
    [[ASFileManager shareInstance] registerDirectoryModelClassString:NSStringFromClass([ASMainBundle class]) withDirectoryType:@"app"];
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath{
    if (self = [super initWithDirectoryPath:directoryPath]) {
        if (self.current.machOFiles.count>0) {
            self.exeFile = [self.current.machOFiles firstObject];
            self.appPath = directoryPath;
        }
    }
    return self;
}

@end
