//
//  ASNibDirectory.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASNibDirectory.h"
#import "ASNibFile.h"
#import "ASImageFile.h"
#import "ASCarFile.h"
#import "ASFramework.h"
#import "ASFileManager.h"

@implementation ASNibDirectory

+ (void)load{
    [[ASFileManager shareInstance] registerDirectoryModelClassString:NSStringFromClass([ASNibDirectory class]) withDirectoryType:@"nib"];
}

- (NSMutableArray *)nibs{
    if (!_nibs) {
        _nibs = [NSMutableArray array];
    }
    return _nibs;
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath{
    if (self = [super initWithDirectoryPath:directoryPath]) {
        [self.nibs addObjectsFromArray:self.current.nibFiles];
        NSUInteger dataSize = 0;
        for (ASNibFile * nibFile in self.nibs) {
            dataSize += nibFile.inputSize;
        }
        self.nibSize = dataSize;
    }
    return self;
}

@end
