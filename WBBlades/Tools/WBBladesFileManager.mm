//
//  WBBladesFileManager.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/14.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesFileManager.h"
#import "WBBladesCMD.h"
#import "WBBladesTool.h"

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
    uint32_t cputype = *(uint32_t*)((uint8_t *)[fileData bytes] + 4);
    if (!fileData || cputype != CPU_TYPE_ARM64 ) {
        NSLog(@"文件读取失败，请输入使用arm64真机的debug包");
        return nil;
    }
    return fileData;
}
+ (NSData *)readArm64DylibFromFile:(NSString *)filePath{

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
    uint32_t cputype = *(uint32_t*)((uint8_t *)[fileData bytes] + 4);
    if (!fileData || cputype != CPU_TYPE_ARM64) {
        NSLog(@"文件读取失败，请输入使用arm64真机的debug包");
        return nil;
    }
    return fileData;
}

#pragma mark Crash
static NSMutableArray *_crashStacks = nil;
static NSMutableArray *_usefulCrashLine = nil;
+ (NSArray *)obtainAllCrashOffsets:(NSString *)crashLogPath appPath:(NSString *)appPath{
    if (!crashLogPath) {
        return nil;
    }
    
    if (!_crashStacks) {
        _crashStacks = [NSMutableArray array];
    }
    if (!_usefulCrashLine) {
        _usefulCrashLine = [NSMutableArray array];
    }
    
    [_crashStacks removeAllObjects];
    [_crashStacks removeAllObjects];
    
    NSString *lastPathComponent = [appPath lastPathComponent];
    NSArray *tmp = [lastPathComponent componentsSeparatedByString:@"."];
    NSString *execName = @"";
    if ([tmp count] == 2) {
        NSString *fileType = [tmp lastObject];
        if ([fileType isEqualToString:@"app"]) {
            execName = [tmp firstObject];
        }
    }
    
    NSString *fileString = [self importCrashLogStack:crashLogPath];
    // 获得此app的崩溃地址
    NSArray *crashInfoLines = [fileString componentsSeparatedByString:@"\n"];
    NSMutableArray *crashOffsets = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < crashInfoLines.count; i++) {
        
        NSString *crashLine = crashInfoLines[i];
        NSArray *compos = [crashLine componentsSeparatedByString:@" "];
        if (compos.count > 2) {
            if ([crashLine containsString:execName]) {
                NSString *offset = compos.lastObject;
                if (offset.longLongValue) {
                    [crashOffsets addObject:[NSString stringWithString:offset]];
                }
                [_usefulCrashLine addObject:crashLine];
            }
        }
        [_crashStacks addObject:crashLine];
    }
    return crashOffsets;
}

+ (NSString *)importCrashLogStack:(NSString *)logPath {
    NSString *dataString = [[NSString alloc]initWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil];
    NSArray *lines = [dataString componentsSeparatedByString:@"\n"];
    
    NSMutableArray *array = [NSMutableArray array];
    NSString *binaryAddress = @"";
    NSString *backtraceAddress = @"";
    NSUInteger backtraceIndex = -1;
    BOOL found = NO;
    for (NSInteger i = 0; i<lines.count; i++) {
        NSString *line = lines[i];
        if ([line hasPrefix:@"Last Exception"]) {//找到第一个Thread
            found = YES;
        }else if(found && ([line hasPrefix:@"(0x"] && [lines[i-1]  hasPrefix:@"Last Exception"])){
            backtraceAddress = line;
            backtraceIndex = i;
        }else if(found && ([line hasPrefix:@"Binary"] || [line hasPrefix:@"0x"])){
            if (i+1 < lines.count) {//Binary Image：的下一行
                binaryAddress = lines[i+1];
            }
            break;
        }
        [array addObject:line];
    }
    
    //特殊处理Last Exception Backtrace中包含多个地址的情况
    if (backtraceAddress && backtraceAddress.length > 0 && binaryAddress && binaryAddress.length >0) {
        NSArray *addressLines = [self obtainLastExceptionCrashModels:backtraceAddress
                                                       binaryAddress:binaryAddress];
        if (addressLines && addressLines.count > 0) {
            [array replaceObjectAtIndex:backtraceIndex withObject:@""];
            [array insertObjects:addressLines atIndexes:[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(backtraceIndex, addressLines.count)]];
        }
    }
    
    NSMutableString *resultString = [NSMutableString string];
    for (NSString *line in array) {
        [resultString appendString:[NSString stringWithFormat:@"%@\n",line]];
    }
    return [resultString copy];
}

/**
* 从Last Exception Backtrace中获取与当前进程的地址，并转为Model
*/
+ (NSArray<NSString*>*)obtainLastExceptionCrashModels:(NSString *)string
                                        binaryAddress:(NSString*)between {
    NSMutableArray *array = [NSMutableArray array];
    
    NSArray *processArray = [between componentsSeparatedByString:@" "];
    if (processArray.count < 4) {
        return nil;
    }
    NSString *processStart = [processArray firstObject];//当前进程的起始地址
    NSInteger startNum = [self numberWithHexString:[processStart stringByReplacingOccurrencesOfString:@"0x" withString:@""]];
    NSString *processEnd = processArray[2];//当前进程的结束地址
    NSString *processName = processArray[3];//当前进程名
    
    NSString *newString = [string stringByReplacingOccurrencesOfString:@"(" withString:@""];
    newString = [newString stringByReplacingOccurrencesOfString:@")" withString:@""];
    NSArray *crashAddresses = [newString componentsSeparatedByString:@" "];//获取所有地址
    if (crashAddresses && crashAddresses.count > 0) {
        for (NSInteger i = 0; i<crashAddresses.count; i++) {
            NSString *string = crashAddresses[i];
            //当前地址小于结束地址，大于起始地址
            if (([string integerValue] < [processEnd integerValue]) && ([string integerValue] > [processStart integerValue])) {
                NSInteger stringNum = [self numberWithHexString:[string stringByReplacingOccurrencesOfString:@"0x" withString:@""]];
                NSInteger offsetNum = stringNum - startNum;
                NSString *stack = [NSString stringWithFormat:@"%li %@ %lu",i,processName,offsetNum];
                [array addObject:stack];
            } else {
                [array addObject:string];
            }
        }
    }
    
    return [array copy];
}

+ (NSString *)obtainOutputLogWithResult:(NSDictionary *)result{
    NSMutableArray *outputArr = [[NSMutableArray alloc] init];
    for (NSString *infoStr in _crashStacks) {
        if (![_usefulCrashLine containsObject:infoStr]) {
            [outputArr addObject:infoStr];
        } else {
            NSArray *infoComps = [infoStr componentsSeparatedByString:@" "];
            NSArray *infos = [infoStr componentsSeparatedByString:@"0x"];
            NSString *offset = infoComps.lastObject;
            if (offset) {
                NSString* methodName = [result valueForKey:offset][@"symbol"];
                if (methodName) {
                    NSString *resultStr = [NSString stringWithFormat:@"%@ %@",infos.firstObject,methodName];
                    NSString *result = [resultStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
                    [outputArr addObject:result];
                } else {
                    [outputArr addObject:infoStr];
                }
            }
        }
    }
    
    [_crashStacks removeAllObjects];
    [_usefulCrashLine removeAllObjects];
    NSString *outputLog = [outputArr componentsJoinedByString:@"\n"];
    return outputLog;
}


/**
* 十六进制字符串转数字
*/
+ (NSInteger)numberWithHexString:(NSString *)hexString {
    const char *hexChar = [hexString cStringUsingEncoding:NSUTF8StringEncoding];
    int hexNumber;
    sscanf(hexChar, "%x", &hexNumber);
    return (NSInteger)hexNumber;
}

@end
