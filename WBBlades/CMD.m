//
//  CMD.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/25.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "CMD.h"


const char *cmd(NSString *cmd){
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    // 开始task
    NSFileHandle *file = [pipe fileHandleForReading];
    [task launch];
    
    // 获取运行结果
    NSData *data = [file readDataToEndOfFile];
    return [data bytes];
}

void colorPrint(NSString *info){
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSString *cmd = [NSString stringWithFormat:@"echo -e '\e[1;36m %@ \e[0m'",info];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    
    [task launch];
}

void stripFile(NSString *filePath){
    //去除bitcode信息
    NSLog(@"正在去除bitcode中间码...");
    NSString *bitcodeCmd = [NSString stringWithFormat:@"xcrun bitcode_strip -r %@_copy -o %@_copy",filePath,filePath];
    cmd(bitcodeCmd);
    //剥离符号表
    NSLog(@"正在剥离符号表...");
    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -x %@_copy",filePath];
    cmd(stripCmd);
}


