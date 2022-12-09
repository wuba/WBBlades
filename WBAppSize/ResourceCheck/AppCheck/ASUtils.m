//
//  ASUtils.m
//  WBAppSize
//
//  Created by Shwnfee on 2022/11/2.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASUtils.h"
#import "NSData+UTF8.h"
@implementation ASUtils

+ (NSString *)fileNameStripSubfix:(NSString *)fileName{
    NSString * fileType = [fileName pathExtension];
    if (![fileType isKindOfClass:[NSString class]] || [fileType length]==0) {
        return fileName;
    }
    fileType = [@"." stringByAppendingString:fileType];
    if ([fileType length]>[fileName length]) {
        return fileName;
    }
    return [fileName stringByReplacingCharactersInRange:NSMakeRange(fileName.length-fileType.length, fileType.length) withString:@""];
}

+ (NSUInteger)bytesSizeForFile:(NSString *)path{
    NSDictionary *fileAttributes =[[NSFileManager defaultManager] attributesOfItemAtPath: path error:nil];
    id size = [fileAttributes objectForKey:NSFileSize];
    if ([size respondsToSelector:@selector(unsignedIntegerValue)]) {
        return [size unsignedIntegerValue];
    }
    NSData * data = [NSData dataWithContentsOfFile:path];
    return data.length;
}

+ (NSString *)typeInPath:(NSString *)path{
    NSArray * array = [path componentsSeparatedByString:@"."];
    if (array.count == 0) {
        return nil;
    }
    return [array lastObject];
}

+ (NSString*)discriptionWithByteSize:(NSUInteger)size{
    double length = 1000.0;
//    BOOL length = 1024;
    if (size<length) {
        return [NSString stringWithFormat:@"%lu Bytes",size];
    }else if (size>=length && size<length*length) {
        return [NSString stringWithFormat:@"%.2lf KB",((CGFloat)size/length)];
    }else if (size>=length*length && size<length*length*length){
        return [NSString stringWithFormat:@"%.2lf MB",((CGFloat)size/(length*length))];
    }
    return [NSString stringWithFormat:@"%.2lf GB",((CGFloat)size/(length*length*length))];
}

+ (NSURL *)cachePathURL{
    NSArray * urls= [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask];
    NSURL * cachePath = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@",[urls firstObject],@"AppSize/"]];
    return cachePath;
}

+ (NSDictionary *)obtainNibInfoForNibPath:(NSString *)nibPath{
    NSFileManager * fm = [NSFileManager defaultManager];
    BOOL isDirectory;
    BOOL ret = [fm fileExistsAtPath:nibPath isDirectory:&isDirectory];
    if ((!ret)||isDirectory) {
        return @{};
    }
    NSData * nibData = [NSData dataWithContentsOfFile:nibPath];
    NSString * stringOnNibOfUTF8 = [[NSString alloc] initWithData:[nibData UTF8Data]  encoding:NSUTF8StringEncoding];
    NSArray * subStrings = [stringOnNibOfUTF8 componentsSeparatedByString:[nibData UTF8ReplacementStr]];
    NSMutableDictionary * resultInfo = [NSMutableDictionary dictionary];
    for (NSString * subStr in subStrings) {
        if (subStr.length>0) {
            [resultInfo setObject:@"" forKey:subStr];
        }
    }
    return resultInfo;
}

+ (NSArray *)customUsingNameForFileName:(NSString *)fileName{
    static NSDictionary * customUsingName;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle * mainBundle = [NSBundle mainBundle];
        NSString * plistPath = [mainBundle pathForResource:@"custom_using_name" ofType:@"plist"];
        customUsingName = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    });
    if (![customUsingName isKindOfClass:[NSArray class]]) {
        return nil;
    }
    return customUsingName[fileName];
}

@end
