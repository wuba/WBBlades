//
//  AppProjectCheck.m
//  AppSizeManager
//
//  Created by wbblades on 2022/3/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "AppProjectCheck.h"
#import "WBBladesCMD.h"

@implementation AppProjectCheck

// 检测源码工程文件中是否开启LTO
static BOOL checkHasLTO(NSString *prjPath){
    //查找.xcodeproj文件
    NSFileManager* fileManager=[NSFileManager defaultManager];
    NSEnumerator* enumerator = [fileManager enumeratorAtPath:prjPath];
    NSString* filename;
    while(filename=[enumerator nextObject]){
       if ([[filename pathExtension] isEqualToString:@"xcodeproj"] && ![filename isEqualToString:@"Pods/Pods.xcodeproj"]) {
           NSLog(@"%@",filename);
           NSString *xcodeprojPath = [NSString stringWithFormat:@"%@/%@/project.pbxproj", prjPath, filename];
           NSString *grepCmd = [NSString stringWithFormat:@"cat %@|grep 'LLVM_LTO = YES'| wc -l",xcodeprojPath];
           NSData *res = cmd(grepCmd);
           NSString *rowstr = [[NSString alloc] initWithData:res encoding:NSUTF8StringEncoding];
           NSInteger row = [rowstr integerValue];
           if (row > 0) {
               return YES;
           }
        }
    }
    return NO;
}

@end
