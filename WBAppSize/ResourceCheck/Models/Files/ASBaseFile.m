//
//  ASBaseFile.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseFile.h"
#import "ASFileManager.h"
#import "ASUtils.h"
NSString * kASFileUpdateNotification = @"kASFileUpdateNotification";

@implementation ASBaseFile

+ (BOOL)checkFileTypeByPath:(NSString *)filePath{
    return NO;
}

+ (instancetype)fileWithPath:(NSString *)filePath{
    ASBaseFile * file = [[[self class] alloc] initWithFilePath:filePath];
    return file;
}

- (instancetype)initWithFilePath:(NSString *)filePath{
    if (self = [super init]) {
        self.filePath = filePath;
        self.fileName = [NSString stringWithFormat:@"%@",[filePath lastPathComponent]];
        self.usingState = ASFileUsingUnKnow;
        self.inputSize = [ASUtils bytesSizeForFile:filePath];
        
    }
    return self;
}

- (void)setFilePath:(NSString *)filePath{
    _filePath = filePath;

    NSArray * pathComponents = [filePath pathComponents];
    __weak ASBaseFile * weakSelf = self;
    [pathComponents enumerateObjectsWithOptions:NSEnumerationReverse usingBlock:^(NSString * pathComponent, NSUInteger idx, BOOL * _Nonnull stop) {
        if ([pathComponent hasSuffix:@".bundle"]) {
            * stop = YES;
            weakSelf.bundleName = pathComponent;
        }
    }];
    if (!self.bundleName) {
        self.bundleName = @"main";
    }
    [pathComponents enumerateObjectsWithOptions:NSEnumerationReverse usingBlock:^(NSString * pathComponent, NSUInteger idx, BOOL * _Nonnull stop) {
        if ([pathComponent hasSuffix:@".framework"]) {
            * stop = YES;
            weakSelf.frameworkName = pathComponent;
        }
    }];
    self.fileName = [filePath lastPathComponent];
    self.usingState = ASFileUsingUnKnow;
    self.inputSize = [ASUtils bytesSizeForFile:filePath];
}

- (void)setFileName:(NSString *)fileName{
    _fileName = fileName;
    _fileType = nil;
    [self fileType];
    self.usingNames = nil;
    [self mayUsingNames];
}

- (NSString *)fileType{
    if (_fileType) {
        return _fileType;
    }
    if (!self.fileName) {
        return @"unkown";
    }
    NSArray * fileNameParts = [self.fileName componentsSeparatedByString:@"."];
    if (fileNameParts.count<2) {
        _fileType = @"unkown";
    }
    _fileType = [fileNameParts lastObject];
    return _fileType;
}

- (NSArray *)addtionUsingNames{
    //子类实现
    return @[];
}

- (void)appendBundlePath{
    if (![self.bundleName isKindOfClass:[NSString class]] || [self.bundleName isEqualToString:@"main"]) {
        return;
    }
    NSString * inBundlePath = [self inBundlePath];
    if ([inBundlePath isKindOfClass:[NSString class]]&&[inBundlePath length]>0) {
        NSMutableArray * namesWithBundle = [self.usingNames mutableCopy];
        for (NSString * usingName in self.usingNames) {
            NSString * name = [NSString stringWithFormat:@"%@%@",inBundlePath,usingName];
            [namesWithBundle addObject:name];
        }
        self.usingNames = namesWithBundle;
    }
    if ([self.fileName containsString:@"OpenBiometricViewFace"]) {
        NSLog(@"");
    }
}

- (NSString *)inBundlePath{
    if (![self.bundleName isKindOfClass:[NSString class]] || [self.bundleName isEqualToString:@"main"]) {
        return nil;
    }
    NSRange bundleNameRange = [self.filePath rangeOfString:self.bundleName];
    if (bundleNameRange.location == NSNotFound || bundleNameRange.location>=self.filePath.length) {
        return nil;
    }
    NSString * inBundlePath = [self.filePath substringFromIndex:bundleNameRange.location];
    if (inBundlePath.length<self.fileName.length) {
        return nil;
    }
    inBundlePath = [inBundlePath substringToIndex:inBundlePath.length-self.fileName.length];
    return inBundlePath;
}


- (NSArray *)mayUsingNames{
    if (self.usingNames) {
        return self.usingNames;
    }
    NSMutableArray * usingNames = [NSMutableArray array];
    if (self.fileName) {
        [usingNames addObject:self.fileName];
        [usingNames addObject:[ASUtils fileNameStripSubfix:self.fileName]];
        NSArray * customUsingName = [ASUtils customUsingNameForFileName:self.fileName];
        if ([customUsingName isKindOfClass:[NSArray class]]) {
            [usingNames addObjectsFromArray:customUsingName];
        }
    }
    NSArray * addtionUsingName =  [self addtionUsingNames];
    if ([addtionUsingName isKindOfClass:[NSArray class]]) {
        [usingNames addObjectsFromArray:addtionUsingName];
    }
    self.usingNames = usingNames;
    [self appendBundlePath];
    return self.usingNames;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@,size:%lu", self.fileName,self.inputSize];
}

- (void)postDataUpdateNotification{
    [self postDataUpdateNotificationUserInfo:nil];
}

- (void)postDataUpdateNotificationUserInfo:(NSDictionary *)userInfo{
    if (![userInfo isKindOfClass:[NSDictionary class]]) {
        [[NSNotificationCenter defaultCenter] postNotificationName:kASFileUpdateNotification object:self];
        return;
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:kASFileUpdateNotification object:self userInfo:userInfo];
}


@end
