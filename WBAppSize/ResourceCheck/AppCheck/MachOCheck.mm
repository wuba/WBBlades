//
//  MachOCheck.m
//  AppSizeManager
//
//  Created by wbblades on 2022/3/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "MachOCheck.h"
#import "WBBladesFileManager.h"
//#import "WBBladesCMD.h"
#import "WBBladesDefines.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import "WBBladesScanManager+UnuseClassScan.h"

static NSMutableSet *s_classSet;

@implementation MachOCheck

// 检测macho中__TEXT中是否有段迁移，并且预测段迁移的优化量大小
+ (CGFloat) checkTEXTHasMigratedSize:(NSString *)libPath {
    CGFloat optSize = 0.0;
    NSData *fileData = [WBBladesFileManager readFromFile:libPath];
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
            NSString *segName = [[NSString alloc] initWithUTF8String:segmentCommand.segname];
            if ([segName isEqual:SEGMENT_TEXT]) {
//                BOOL hasTextSec = NO;
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *sectionName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    if ([sectionName isEqual:TEXT_TEXT_SECTION]) {
                        // 获取SEGMENT_TEXT的filesize，加密会影响60%左右的压缩率
                        optSize = segmentCommand.filesize * 0.6 /1000.0/1000.0;
//                        NSLog(@"找到了__TEXT__text");
//                        hasTextSec = YES;
//                        free(cmd);
//                        return hasTextSec;
                    }
                    currentSecLocation += sizeof(section_64);
                }
                NSLog(@"__TEXT__text迁移了");
//                return hasTextSec;
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    return optSize;
}

//检测frameworks动态库中的macho是否已经strip，并返回优化值
+ (NSDictionary*) checkHasStripedFrameworks:(NSString *)appPath {
    NSString *dylibPath = [NSString stringWithFormat:@"%@/Frameworks", appPath];
    // 遍历其中的.framework动态库
    NSFileManager * fileManger = [NSFileManager defaultManager];
    BOOL isDir = YES;
    BOOL isExist = [fileManger fileExistsAtPath:dylibPath isDirectory:&isDir];
    if (!isExist) {
        return nil;
    }
    NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:dylibPath error:nil];
    //enumerate current directory's files
    NSMutableDictionary *resDic = [NSMutableDictionary new];
    for (NSString *dyName in dirArray) {
        NSArray *splitName = [dyName componentsSeparatedByString:@"."];
        if ([splitName[1] isEqualToString:@"dylib"]) {
            continue;
        }
        NSString *dyFilePath = [dylibPath stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/%@", dyName, splitName[0]]];
        NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -xS %@ -o %@_strip",dyFilePath, dyFilePath];
        cmd(stripCmd);
        // 比较strip前后的文件大小
        NSData *beforeData = [NSData dataWithContentsOfFile:dyFilePath];
        NSData *afterData = [NSData dataWithContentsOfFile:[NSString stringWithFormat:@"%@_strip", dyFilePath]];
        NSUInteger diffLen = beforeData.length - afterData.length;
        if (diffLen > 0) {
            resDic[dyName] = @(diffLen/1000.0/1000.0);
        }
        NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@", [NSString stringWithFormat:@"%@_strip", dyFilePath]];
        cmd(rmCmd);
    }
    return resDic;
}

// 
+ (NSArray *)scanUnusedClassesInFile:(NSString *)appPath {
    s_classSet = [NSMutableSet set];
    //read binary files, scan all libs and classes to find unused classes
    NSArray *resultArr = [WBBladesScanManager scanAllClassWithFileData:[WBBladesFileManager readArm64FromFile:appPath] classes:s_classSet progressBlock:nil];
    float totalSize = 0;
    NSMutableSet *classset = [NSMutableSet set];
    NSDictionary *ocDic = resultArr[0];
    //合并oc和swift的集合<类名NSString,类大小NSNumber>
    for (NSString *className in ocDic.allKeys) {
        float clzSize = [ocDic[className] floatValue] / 1000.0;
        totalSize += clzSize;
        NSString *singleRes = [NSString stringWithFormat:@"%@", className];
//        NSString *singleRes = [NSString stringWithFormat:@"%@, 大小：%.1fK", className, clzSize];
        [classset addObject:singleRes];
    }
    NSDictionary *swiftDic = resultArr[1];
    for (NSString *className in swiftDic.allKeys) {
        float clzSize = [swiftDic[className] floatValue] / 1000.0;
        totalSize += clzSize;
        NSString *singleRes = [NSString stringWithFormat:@"%@", className];
//        NSString *singleRes = [NSString stringWithFormat:@"%@, 大小：%.1fK", className, clzSize];
        [classset addObject:singleRes];
    }
    //write results to file
    NSString *outputPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    outputPath = [outputPath stringByAppendingPathComponent:@"UnusedClass.plist"];
    [classset.allObjects writeToFile:outputPath atomically:YES];
    return @[outputPath, classset, @(totalSize)];
}

+ (NSString *)storeOptimizePath
{
    NSString *outputPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    outputPath = [outputPath stringByAppendingPathComponent:@"imgCompress"];
    return outputPath;
}

+ (void)cleanCompressImageRootPath
{
    [MachOCheck cleanPath:[MachOCheck storeOptimizePath]];
}

+ (void)cleanPath:(NSString *)rootDir
{
    NSString *clCmd = [NSString stringWithFormat:@"if [ ! -d '%@' ];then mkdir %@;else rm -rf %@/*; fi;", rootDir, rootDir, rootDir];
    cmd(clCmd);
}

+ (void)copyFileFromPath:(NSString *)from toPath:(NSString *)to
{
    NSArray *splitArr = [to componentsSeparatedByString:@"/"];
    NSString *imageDir = [to stringByReplacingOccurrencesOfString:splitArr.lastObject withString:@""];
    NSString *cpCmd = [NSString stringWithFormat:@"if [ ! -d '%@' ];then mkdir %@;fi;cp -f %@ %@", imageDir, imageDir, from, to];
    cmd(cpCmd);
}

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

/**
 预处理下APP的可执行文件
 */
+ (void)preHandleMainBinary:(NSString *)filePath {
    filePath = [filePath stringByReplacingOccurrencesOfString:@" " withString:@"\\ "];
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (fileData.length < sizeof(uint32_t) ) {
        return;
    }
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        NSString *thinCmd = [NSString stringWithFormat:@"lipo -archs %@",filePath];
        NSArray *archs = [[[NSString alloc] initWithData:cmd(thinCmd) encoding:NSUTF8StringEncoding] componentsSeparatedByString:@" "];
        if (archs.count >= 1) {
            thinCmd = [NSString stringWithFormat:@"lipo %@ -thin arm64  -output %@",filePath, filePath];
            NSLog(@"正在提取arm64架构:%@",filePath); // Strip symbol table.
            cmd(thinCmd);
        }
    }
//    // 如果是debug包，要进行strip
//    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -xS %@ -o %@",filePath, filePath];
//    cmd(stripCmd);
    
}
@end
