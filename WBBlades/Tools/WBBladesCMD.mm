//
//  WBBladesCMD.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/12/25.
//  Copyright © 2019 58.com. All rights reserved.
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

static int i = 0;
NSString* createDeskTempDirectory() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDesktopDirectory, NSUserDomainMask, YES);
    NSString *theDesktopPath = [paths.firstObject stringByAppendingFormat:@"/wbbladestmp"];
    NSTimeInterval timeInterval =  [[NSDate date] timeIntervalSince1970];
    theDesktopPath = [theDesktopPath stringByAppendingFormat:@"/%@%@", @(timeInterval), @(i++)];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL direct;
    if (![fileManager fileExistsAtPath:theDesktopPath isDirectory:&direct]) {
        [fileManager createDirectoryAtPath:theDesktopPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return theDesktopPath;
}

void rmAppIfIpa(NSString *filePath){
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    NSString *fileName = filePath.lastPathComponent;
    NSString *fileType = [fileName componentsSeparatedByString:@"."].lastObject;
    if ([fileType isEqualToString:@"ipa"]) {
        //创建同级目录
        NSString *parentPath = filePath.stringByDeletingLastPathComponent;
        NSString *tmpPath = [parentPath stringByAppendingFormat:@"/tmp/"];
//        cmd([NSString stringWithFormat:@"rm -rf %@",tmpPath]);
        NSString *theDesktopPath = createDeskTempDirectory();
        cmd([NSString stringWithFormat:@"mv -f %@ %@",tmpPath, theDesktopPath]);
    }
}

NSString* getAppPathIfIpa(NSString *filePath){
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    rmAppIfIpa(filePath);

    NSString *fileName = filePath.lastPathComponent;
    NSString *fileType = [fileName componentsSeparatedByString:@"."].lastObject;
    if ([fileType isEqualToString:@"ipa"]) {
        NSFileManager *manager = [NSFileManager defaultManager];
        //创建同级目录
        NSString *parentPath = filePath.stringByDeletingLastPathComponent;
        NSString *tmpPath = [parentPath stringByAppendingFormat:@"/tmp/"];
        NSString *copyPath = [tmpPath stringByAppendingString:@"copy.ipa"];

        cmd([NSString stringWithFormat:@"mkdir %@",tmpPath]);

        //解压
        [manager copyItemAtPath:filePath toPath:copyPath error:NULL];

        cmd([NSString stringWithFormat:@"unzip -d %@ %@",tmpPath,copyPath]);

        __block NSString *lastFilePath = filePath;
        NSString *payloadPath = [tmpPath stringByAppendingFormat:@"Payload/"];
        BOOL isDirectory;
        if([manager fileExistsAtPath:payloadPath isDirectory:&isDirectory]){
            NSArray *files = [manager contentsOfDirectoryAtPath:payloadPath error:NULL];
            [files enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {

                NSString *file = (NSString *)obj;
                if ([file hasSuffix:@".app"]) {
                    lastFilePath = [payloadPath stringByAppendingString:file];
                    *stop = YES;
                }
            }];
        }
        filePath = lastFilePath;
    }

    return filePath;
}

void stripBitCode(NSString *filePath) {
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
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
}

void stripDysmSymbol(NSString *filePath) {
    NSLog(@"正在剥离符号表..."); // Strip symbol table.
    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -x -S %@_copy",filePath];
    cmd(stripCmd);
}

void copyFile(NSString *filePath) {
    // 替换目录中的空格，以免影响命令行执行
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    NSString *cpCmd = [NSString stringWithFormat:@"cp -f %@ %@_copy",filePath,filePath];
    cmd(cpCmd);
}

void thinFile(NSString *filePath) {
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
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
    if (archs.count >= 1) {
        thinCmd = [NSString stringWithFormat:@"lipo %@_copy -thin arm64  -output %@_copy",filePath,filePath];
        NSLog(@"正在提取arm64架构:%@",filePath); // Strip symbol table.
        cmd(thinCmd);
    }
}

void removeFile(NSString *filePath) {
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
        NSString *theDesktopPath = createDeskTempDirectory();
        NSString *rmCmd = [NSString stringWithFormat:@"mv -f %@ %@", filePath, theDesktopPath];
        cmd(rmCmd);
    }
}

void removeCopyFile(NSString *filePath) {
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    if ([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@_copy", filePath]]) {
        NSString *theDesktopPath = createDeskTempDirectory();
        NSString *rmCmd = [NSString stringWithFormat:@"mv -f %@_copy %@",filePath, theDesktopPath];
        cmd(rmCmd);
    }
}

/**
 actool(apple command line tool)    --filter-for-device-model iPhone7,2（Specify the device） --filter-for-device-os-version 13.0（Specify the system）  --target-device iphone --minimum-deployment-target 9（Specify the minimum version） --platform iphoneos（Specify operation system type）  --compile /Users/a58/Desktop/BottomDlib/BottomDlib/  /Users/a58/Desktop/BottomDlib/BottomDlib/YXUIBase.xcassets （Specify the path where the compiled files are located. If there are multiple paths, concatenate them with spaces.）
 */
void compileXcassets(NSString *path) {
    path = [path stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    NSString *complieCmd = [NSString stringWithFormat:@"actool   --compress-pngs --filter-for-device-model iPhone9,2 --filter-for-device-os-version 13.0  --target-device iphone --minimum-deployment-target 9 --platform iphoneos --compile %@ %@", [path stringByDeletingLastPathComponent],path];
    cmd(complieCmd);
}

// 对已有的Assets.car文件进行3X分片
void appSlicing3XAssetsCar(NSString *path, NSString *thinCarPath) {
    path = [path stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    thinCarPath = [thinCarPath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    NSString *thinCmd = [NSString stringWithFormat:@"assetutil --idiom phone --subtype 570 --scale 3 --display-gamut srgb --graphicsclass MTL2,2 --graphicsclassfallbacks MTL1,2:GLES2,0 --memory 1 --hostedidioms car,watch %@ -o %@", path, thinCarPath];
    cmd(thinCmd);
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

