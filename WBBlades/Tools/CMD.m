//
//  CMD.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/25.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "CMD.h"

static const char *cmd(NSString *cmd){
    
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
    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -x -S %@_copy",filePath];
    cmd(stripCmd);
}

void removeCopyFile(NSString *filePath){
    NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@_copy",filePath];
    cmd(rmCmd);
}

void copyFile(NSString *filePath){
    NSString *cpCmd = [NSString stringWithFormat:@"cp  -f %@ %@_copy",filePath,filePath];
    cmd(cpCmd);
}

void thinFile(NSString *filePath){
    NSString *thinCmd = [NSString stringWithFormat:@"lipo %@_copy -thin arm64  -output %@_copy",filePath,filePath];
    cmd(thinCmd);

}


/**
 actool(apple命令行工具)    --filter-for-device-model iPhone7,2（指定设备） --filter-for-device-os-version 13.0（指定系统）  --target-device iphone --minimum-deployment-target 9（指定最小版本） --platform iphoneos（指定操作系统类型）  --compile /Users/a58/Desktop/BottomDlib/BottomDlib/  /Users/a58/Desktop/BottomDlib/BottomDlib/YXUIBase.xcassets （指定编译文件所在路径，如有多个，加空格拼接即可）
 */
void compileXcassets(NSString *path){
    NSString *complieCmd = [NSString stringWithFormat:@"actool   --compress-pngs --filter-for-device-model iPhone9,2 --filter-for-device-os-version 13.0  --target-device iphone --minimum-deployment-target 9 --platform iphoneos --compile %@ %@",[path stringByDeletingLastPathComponent],path];
    cmd(complieCmd);
}

void removeFile(NSString *filePath){
    NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@",filePath];
    cmd(rmCmd);
}
