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
    NSURL * tmpURL = [NSURL fileURLWithPath:filePath];
    NSData * fileData = [NSMutableData dataWithContentsOfURL:tmpURL
                                 options:NSDataReadingMappedIfSafe
                                                       error:NULL];
    return fileData;
}


@end
