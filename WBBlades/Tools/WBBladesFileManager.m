//
//  WBBladesFileManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesFileManager.h"
#import "WBBladesCMD.h"

@implementation WBBladesFileManager

+ (NSData *)readFromFile:(NSString *)filePath {
    NSURL *tmpURL = [NSURL fileURLWithPath:filePath];
    NSData *fileData = [NSMutableData dataWithContentsOfURL:tmpURL
                                                    options:NSDataReadingMappedIfSafe
                                                      error:NULL];
    if (!fileData) {
        NSLog(@"文件读取失败");
    }
    return fileData;
}

+ (NSData *)readArm64FromFile:(NSString *)filePath {
    
    // Path correction for the app file.
    NSString *lastPathComponent = [filePath lastPathComponent];
    NSArray *tmp = [lastPathComponent componentsSeparatedByString:@"."];
    if ([tmp count] == 2) {
        NSString *fileType = [tmp lastObject];
        if ([fileType isEqualToString:@"app"]) {
            NSString *fileName = [tmp firstObject];
            filePath = [filePath stringByAppendingPathComponent:fileName];
        }
    }
    
    removeCopyFile(filePath);
    
    copyFile(filePath);
    
    thinFile(filePath);    // Remove architectures which are not arm64.
    
    NSURL *tmpURL = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@_copy", filePath]];
    NSData *fileData = [NSMutableData dataWithContentsOfURL:tmpURL
                                                    options:NSDataReadingMappedIfSafe
                                                      error:NULL];
    removeCopyFile(filePath);
    
    if (!fileData) {
        NSLog(@"文件读取失败");
    }
    return fileData;
}

@end
