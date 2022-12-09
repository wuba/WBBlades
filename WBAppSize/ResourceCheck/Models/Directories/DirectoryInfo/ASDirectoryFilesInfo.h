//
//  ASDirectoryFilesInfo.h
//  WBAppSize
//
//  Created by Shwnfee on 2022/11/2.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

@class ASBaseDirectory,ASBaseFile;

@interface ASDirectoryFilesInfo : NSObject

//当前目录下的文件大小
@property (nonatomic, assign) NSUInteger machOSize;
@property (nonatomic, assign) NSUInteger carSize;
@property (nonatomic, assign) NSUInteger nibSize;
@property (nonatomic, assign) NSUInteger pngSize;
@property (nonatomic, assign) NSUInteger jpgSize;
@property (nonatomic, assign) NSUInteger jsonSize;
@property (nonatomic, assign) NSUInteger plistSize;
@property (nonatomic, assign) NSUInteger otherSize;
@property (nonatomic, assign) NSUInteger frameworkSize;
@property (nonatomic, assign) NSUInteger bundleSize;
@property (nonatomic, assign) NSUInteger pluginSize;
@property (nonatomic, assign) NSUInteger totalSize;

@property (nonatomic, strong) NSMutableArray * machOFiles;
@property (nonatomic, strong) NSMutableArray * carFiles;
@property (nonatomic, strong) NSMutableArray * pngFiles;

@property (nonatomic, strong) NSMutableArray * nibFiles;
@property (nonatomic, strong) NSMutableArray * jpgFiles;
@property (nonatomic, strong) NSMutableArray * jsonFiles;
@property (nonatomic, strong) NSMutableArray * plistFlies;
@property (nonatomic, strong) NSMutableArray * otherFiles;
@property (nonatomic, strong) NSMutableArray * allFiles;

@property (nonatomic, strong) NSMutableArray * nibs;
@property (nonatomic, strong) NSMutableArray * frameworks;
@property (nonatomic, strong) NSMutableArray * plugIns;
@property (nonatomic, strong) NSMutableArray * bundles;
@property (nonatomic, strong) NSMutableArray * otherDirectories;
@property (nonatomic, strong) NSMutableArray * allDirectories;
@property (nonatomic, strong) NSMutableArray * allDirectoryPaths;

- (void)recountSize;

- (void)addFile:(ASBaseFile *)file;
- (void)addDirectory:(ASBaseDirectory *)directory;

- (void)descendingSort;
- (void)ascendingSort;
@end
