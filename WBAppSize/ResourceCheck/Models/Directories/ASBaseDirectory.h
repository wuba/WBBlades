//
//  ASBaseDirectory.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>
#import "ASDirectoryFilesInfo.h"

@interface ASBaseDirectory : NSObject

@property (nonatomic, strong) ASDirectoryFilesInfo * current; //当前目录资源信息(不包含子目录)
@property (nonatomic, strong) ASDirectoryFilesInfo * all; //所有资源信息（包含子目录）

@property (nonatomic, strong) NSString * directoryName;
@property (nonatomic, strong) NSString * directoryPath;


@property (nonatomic, assign) BOOL hasReadFiles;
@property (nonatomic, assign) BOOL hasLoadFinished;



+ (instancetype)directoryWithPath:(NSString *)path;

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath;

- (void)appendSubDirectory:(ASBaseDirectory *)directory;

- (void)countSize;
- (void)recountSize;


@end
