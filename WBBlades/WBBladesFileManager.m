//
//  WBBladesFileManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesFileManager.h"

@implementation WBBladesFileManager

+(NSData *)readFromFile:(NSString *)filePath{
    //NSLog(@"file path is: %@", filePath);
    NSURL * tmpURL = [NSURL fileURLWithPath:filePath];
    //NSLog(@"%@", [NSString stringWithFormat:@"%@",tmpURL]);
    NSData * fileData = [NSMutableData dataWithContentsOfURL:tmpURL
                                 options:NSDataReadingMappedIfSafe
                                                       error:NULL];
    //NSLog(@"%@", fileData);
    // Get arm64 from fileData?
    if (!fileData) {
        NSLog(@"文件读取失败");
    }
    return fileData;
}


@end
