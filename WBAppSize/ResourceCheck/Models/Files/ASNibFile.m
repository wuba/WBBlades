//
//  ASNibFile.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASNibFile.h"
#import "ASFileManager.h"
@implementation ASNibFile

+ (void)load{
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASNibFile class]) withFileType:@"nib"];
}

+ (instancetype)fileWithPath:(NSString *)filePath{
    ASNibFile * file = [super fileWithPath:filePath];
    [filePath lastPathComponent];
    //获取Nib名称
    NSArray * pathComponents = [filePath componentsSeparatedByString:@"/"];
    for (NSString * pathComponent in pathComponents) {
        if ([pathComponent hasSuffix:@".nib"]) {
            file.nibName = pathComponent;
            break;
        }
    }
    return file;
}

@end
