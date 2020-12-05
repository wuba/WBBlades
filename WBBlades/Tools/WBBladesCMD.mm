//
//  WBBladesCMD.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/25.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesCMD.h"
#import <mach-o/fat.h>
#import "WBBladesTool.h"
// Execute command in console.
static NSData * cmd(NSString *cmd) {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];  // Start task
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];    // Get execution results.
    return data;
}

void stripFile(NSString *filePath) {

    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (fileData.length < sizeof(uint32_t) ) {
        return;
    }
    if (![WBBladesTool isMachO:fileData]) {
        return;
    }
    NSLog(@"正在去除bitcode中间码...");    // Remove bitcode information.
    NSString *bitcodeCmd = [NSString stringWithFormat:@"xcrun bitcode_strip -r %@_copy -o %@_copy",filePath,filePath];
    cmd(bitcodeCmd);
    
    NSLog(@"正在剥离符号表..."); // Strip symbol table.
    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -x -S %@_copy",filePath];
    cmd(stripCmd);
}

void copyFile(NSString *filePath) {
    NSString *cpCmd = [NSString stringWithFormat:@"cp -f %@ %@_copy",filePath,filePath];
    cmd(cpCmd);
}

void thinFile(NSString *filePath) {
    
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (fileData.length < sizeof(uint32_t) ) {
        return;
    }
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
        return;
    }

    NSString *thinCmd = [NSString stringWithFormat:@"lipo -archs %@_copy",filePath];
    NSArray *archs = [[[NSString alloc] initWithData:cmd(thinCmd) encoding:NSUTF8StringEncoding] componentsSeparatedByString:@" "];
    if (archs.count > 1) {
        thinCmd = [NSString stringWithFormat:@"lipo %@_copy -thin arm64  -output %@_copy",filePath,filePath];
        NSLog(@"正在提取arm64架构"); // Strip symbol table.
        cmd(thinCmd);
    }
}

void removeFile(NSString *filePath) {
    NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@", filePath];
    cmd(rmCmd);
}

void removeCopyFile(NSString *filePath) {
    NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@_copy",filePath];
    cmd(rmCmd);
}

/**
 actool(apple command line tool)    --filter-for-device-model iPhone7,2（Specify the device） --filter-for-device-os-version 13.0（Specify the system）  --target-device iphone --minimum-deployment-target 9（Specify the minimum version） --platform iphoneos（Specify operation system type）  --compile /Users/a58/Desktop/BottomDlib/BottomDlib/  /Users/a58/Desktop/BottomDlib/BottomDlib/YXUIBase.xcassets （Specify the path where the compiled files are located. If there are multiple paths, concatenate them with spaces.）
 */
void compileXcassets(NSString *path) {
    NSString *complieCmd = [NSString stringWithFormat:@"actool   --compress-pngs --filter-for-device-model iPhone9,2 --filter-for-device-os-version 13.0  --target-device iphone --minimum-deployment-target 9 --platform iphoneos --compile %@ %@", [path stringByDeletingLastPathComponent],path];
    cmd(complieCmd);
}

#pragma mark Tools
void colorPrint(NSString *info) {
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSString *cmd = [NSString stringWithFormat:@"echo -e '\e[1;36m %@ \e[0m'",info];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    
    [task launch];
}

NSString *swiftDemangle(NSString *swiftName){
    NSString *swiftOrgNames = @"";
    if ([swiftName hasPrefix:@"_$"]) {
        swiftOrgNames = [swiftName stringByReplacingCharactersInRange:NSMakeRange(0, 2) withString:@""];
    }else if ([swiftName hasPrefix:@"$"]){
        swiftOrgNames = [swiftName stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@""];
    }
    
    if (swiftOrgNames && swiftOrgNames.length > 0) {
        NSString *swiftCmd = [NSString stringWithFormat:@"xcrun swift-demangle %@",swiftOrgNames];
        NSData *data = cmd(swiftCmd);
        NSString *orgString = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
        
        return [[orgString componentsSeparatedByString:@"--->"] lastObject];
    }
    return swiftName;
}
