//
//  ASBaseDirectory.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseDirectory.h"
#import "ASFileManager.h"

@implementation ASBaseDirectory

- (ASDirectoryFilesInfo *)current{
    if (!_current) {
        _current = [[ASDirectoryFilesInfo alloc] init];
    }
    return _current;
}

- (ASDirectoryFilesInfo *)all{
    if (!_all) {
        _all = [[ASDirectoryFilesInfo alloc] init];
    }
    return _all;
}

+ (instancetype)directoryWithPath:(NSString *)path{
    ASBaseDirectory * directory = [[[self class] alloc] initWithDirectoryPath:path];
    return directory;
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath{
    if (self = [super init]) {
        self.hasReadFiles = NO;
        self.directoryPath = directoryPath;
        self.directoryName = [directoryPath lastPathComponent];
        [self loadSubFiles];
    }
    return self;
}

- (void)loadSubFiles{
    NSString * path = self.directoryPath;
    NSFileManager * fileManager = [NSFileManager defaultManager];
    NSArray * subPaths = [fileManager subpathsAtPath:path];
    for (NSString * subPath in subPaths) {
        NSString * filePath = [path stringByAppendingPathComponent:subPath];
        BOOL isDirectory;
        [fileManager fileExistsAtPath:filePath isDirectory:&isDirectory];
        
        BOOL isCurrentDirectory = YES;
        NSArray * subPathComponents = [subPath pathComponents];
        if (subPathComponents.count>1) {
            isCurrentDirectory = NO;
        }
        if (isDirectory) {
            ASBaseDirectory * directory = [[ASFileManager shareInstance] createDirectoryModelByDirectoryPath:filePath];
            if (isCurrentDirectory) {
                [self.current addDirectory:directory];
            }
            [self.all addDirectory:directory];
        }else{
            ASBaseFile * file = [[ASFileManager shareInstance] createFileModelByFilePath:filePath];
            if (isCurrentDirectory) {
                [self.current addFile:file];
            }
            [self.all addFile:file];
        }
    }
    [self countSize];
}

- (void)appendSubDirectory:(ASBaseDirectory *)directory{
    [self.all.machOFiles addObjectsFromArray:directory.all.machOFiles];
    [self.all.carFiles addObjectsFromArray:directory.all.carFiles];
    [self.all.nibFiles addObjectsFromArray:directory.all.nibFiles];
    [self.all.pngFiles addObjectsFromArray:directory.all.pngFiles];
    [self.all.jpgFiles addObjectsFromArray:directory.all.jpgFiles];
    [self.all.jsonFiles addObjectsFromArray:directory.all.jsonFiles];
    [self.all.plistFlies addObjectsFromArray:directory.all.plistFlies];
    [self.all.otherFiles addObjectsFromArray:directory.all.otherFiles];
    [self.all.allFiles addObjectsFromArray:directory.all.allFiles];
    [self.all.nibs addObjectsFromArray:directory.all.nibs];
    [self.all.frameworks addObjectsFromArray:directory.all.frameworks];
    [self.all.plugIns addObjectsFromArray:directory.all.plugIns];
    [self.all.bundles addObjectsFromArray:directory.all.bundles];
    [self.all.otherDirectories addObjectsFromArray:directory.all.otherDirectories];
    [self.all.allDirectories addObjectsFromArray:directory.all.allDirectories];
//    [self.all.allDirectoryPaths addObjectsFromArray:directory.all.allDirectoryPaths];
}

- (void)countSize{
    [self.current recountSize];
    [self.all recountSize];
    [self sort];
}

- (void)sort{
    [self.all descendingSort];
    [self.current descendingSort];
}

- (void)recountSize {
    [self.all recountSize];
    [self.current recountSize];
    [self sort];
}

@end
