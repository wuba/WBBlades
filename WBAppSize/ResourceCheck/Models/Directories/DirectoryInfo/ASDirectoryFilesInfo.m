//
//  ASDirectoryFilesInfo.m
//  WBAppSize
//
//  Created by Shwnfee on 2022/11/2.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASDirectoryFilesInfo.h"
#import "ASBaseFile.h"
#import "ASCarFile.h"
#import "ASFileManager.h"
#import "ASNibFile.h"
#import "ASNibDirectory.h"
#import "ASPlugIn.h"
#import "ASFramework.h"
#import "ASBundle.h"
#import "ASMainBundle.h"

@implementation ASDirectoryFilesInfo

- (instancetype)init{
    if (self = [super init]) {
        self.machOSize = 0;
        self.carSize = 0;
        self.nibSize = 0;
        self.pngSize = 0;
        self.jpgSize = 0;
        self.jsonSize = 0;
        self.plistSize = 0;
        self.otherSize = 0;
        self.totalSize = 0;
    }
    return self;
}

- (NSMutableArray *)machOFiles{
    if (!_machOFiles) {
        _machOFiles = [NSMutableArray array];
    }
    return _machOFiles;
}

- (NSMutableArray *)carFiles{
    if (!_carFiles) {
        _carFiles = [NSMutableArray array];
    }
    return _carFiles;
}

- (NSMutableArray *)nibFiles{
    if (!_nibFiles) {
        _nibFiles = [NSMutableArray array];
    }
    return _nibFiles;
}

- (NSMutableArray *)pngFiles{
    if (!_pngFiles) {
        _pngFiles = [NSMutableArray array];
    }
    return _pngFiles;
}

- (NSMutableArray *)jpgFiles{
    if (!_jpgFiles) {
        _jpgFiles = [NSMutableArray array];
    }
    return _jpgFiles;
}

- (NSMutableArray *)jsonFiles{
    if (!_jsonFiles) {
        _jsonFiles = [NSMutableArray array];
    }
    return _jsonFiles;
}

- (NSMutableArray *)plistFlies{
    if (!_plistFlies) {
        _plistFlies = [NSMutableArray array];
    }
    return _plistFlies;
}

- (NSMutableArray *)otherFiles{
    if (!_otherFiles) {
        _otherFiles = [NSMutableArray array];
    }
    return _otherFiles;
}

- (NSMutableArray *)allDirectories{
    if (!_allDirectories) {
        _allDirectories = [NSMutableArray array];
    }
    return _allDirectories;
}

- (NSMutableArray *)nibs{
    if (!_nibs) {
        _nibs = [NSMutableArray array];
    }
    return _nibs;
}

- (NSMutableArray *)frameworks{
    if (!_frameworks) {
        _frameworks = [NSMutableArray array];
    }
    return _frameworks;
}

- (NSMutableArray *)plugIns{
    if (!_plugIns) {
        _plugIns = [NSMutableArray array];
    }
    return _plugIns;
}

- (NSMutableArray *)bundles{
    if (!_bundles) {
        _bundles = [NSMutableArray array];
    }
    return _bundles;
}

- (NSMutableArray *)otherDirectories{
    if (!_otherDirectories) {
        _otherDirectories = [NSMutableArray array];
    }
    return _otherDirectories;
}

- (NSMutableArray *)allDirectoryPaths{
    if (!_allDirectoryPaths) {
        _allDirectoryPaths = [NSMutableArray array];
    }
    return _allDirectoryPaths;
}

- (NSMutableArray *)allFiles{
    if (!_allFiles) {
        _allFiles = [NSMutableArray array];
    }
    return _allFiles;
}

- (NSUInteger)machOSize{
    if (_machOSize !=0) {
        return _machOSize;
    }
    for (ASBaseFile * file in self.machOFiles) {
        _machOSize += file.inputSize;
    }
    return _machOSize;
}

- (NSUInteger)carSize{
    if (_carSize !=0) {
        return _carSize;
    }
    for (ASCarFile * file in self.carFiles) {
        if (file.strippedSize>0) {
            _carSize += file.strippedSize;
        }else{
            _carSize += file.inputSize;
        }
    }
    return _carSize;
}

- (NSUInteger)nibSize{
    if (_nibSize !=0) {
        return _nibSize;
    }
    for (ASBaseFile * file in self.nibFiles) {
        _nibSize += file.inputSize;
    }
    return _nibSize;
}

- (NSUInteger)pngSize{
    if (_pngSize !=0) {
        return _pngSize;
    }
    for (ASBaseFile * file in self.pngFiles) {
        _pngSize += file.inputSize;
    }
    return _pngSize;
}


- (NSUInteger)jpgSize{
    if (_jpgSize !=0) {
        return _jpgSize;
    }
    for (ASBaseFile * file in self.jpgFiles) {
        _jpgSize += file.inputSize;
    }
    return _jpgSize;
}

- (NSUInteger)jsonSize{
    if (_jsonSize !=0) {
        return _jsonSize;
    }
    for (ASBaseFile * file in self.jsonFiles) {
        _jsonSize += file.inputSize;
    }
    return _jsonSize;
}

- (NSUInteger)plistSize{
    if (_plistSize !=0) {
        return _plistSize;
    }
    for (ASBaseFile * file in self.plistFlies) {
        _plistSize += file.inputSize;
    }
    return _plistSize;
}

- (NSUInteger)otherSize{
    if (_otherSize !=0) {
        return _otherSize;
    }
    for (ASBaseFile * file in self.otherFiles) {
        _otherSize += file.inputSize;
    }
    return _otherSize;
}

- (NSUInteger)frameworkSize{
    if (_frameworkSize !=0) {
        return _frameworkSize;
    }
    for (ASBaseDirectory * directory in self.frameworks) {
        _frameworkSize += directory.all.totalSize;
    }
    return _frameworkSize;
}

- (NSUInteger)bundleSize{
    if (_bundleSize !=0) {
        return _bundleSize;
    }
    for (ASBaseDirectory * directory in self.bundles) {
        _bundleSize += directory.all.totalSize;
    }
    return _bundleSize;
}

- (NSUInteger)pluginSize{
    if (_pluginSize !=0) {
        return _pluginSize;
    }
    for (ASBaseDirectory * directory in self.plugIns) {
        _pluginSize += directory.all.totalSize;
    }
    return _pluginSize;
}

- (NSUInteger)totalSize{
    if (_totalSize !=0) {
        return _totalSize;
    }
    for (ASBaseFile * file in self.allFiles) {
        if ([file isKindOfClass:[ASCarFile class]]) {
            ASCarFile * carFile = (ASCarFile *)file;
            if (carFile.strippedSize>0) {
                _totalSize += carFile.strippedSize;
            }else{
                _totalSize += file.inputSize;
            }
        }else{
            _totalSize += file.inputSize;
        }
    }
    return _totalSize;
}

+ (NSUInteger)readSizeByItem:(id)item{
    NSUInteger size = 0;
    if ([item isKindOfClass:[ASBaseFile class]]) {
        size = [(ASBaseFile *)item inputSize];
    }else if ([item isKindOfClass:[ASBaseDirectory class]]){
        size = [(ASBaseDirectory *)item all].totalSize;
    }
    return size;
}

- (NSMutableArray *)sortArray:(NSMutableArray *)array isAscending:(BOOL)ascending{
    [array sortUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        NSUInteger size_1 = [ASDirectoryFilesInfo readSizeByItem:obj1];
        NSUInteger size_2 = [ASDirectoryFilesInfo readSizeByItem:obj2];
        if (size_1<size_2) {
            return ascending ? NSOrderedAscending:NSOrderedDescending;
        }else if (size_1>size_2) {
            return ascending ? NSOrderedDescending:NSOrderedAscending;
        }
        return NSOrderedSame;
    }];
    return array;
}

- (void)_ascendingSort:(BOOL)ascending{
    [self sortArray:self.machOFiles isAscending:ascending];
    [self sortArray:self.carFiles isAscending:ascending];
    [self sortArray:self.pngFiles isAscending:ascending];
    [self sortArray:self.nibFiles isAscending:ascending];
    [self sortArray:self.jpgFiles isAscending:ascending];
    [self sortArray:self.jsonFiles isAscending:ascending];
    [self sortArray:self.plistFlies isAscending:ascending];
    [self sortArray:self.otherFiles isAscending:ascending];
    [self sortArray:self.allFiles isAscending:ascending];
    [self sortArray:self.nibs isAscending:ascending];
    [self sortArray:self.frameworks isAscending:ascending];
    [self sortArray:self.plugIns isAscending:ascending];
    [self sortArray:self.bundles isAscending:ascending];
    [self sortArray:self.otherDirectories isAscending:ascending];
    [self sortArray:self.allDirectories isAscending:ascending];
    [self sortArray:self.allDirectoryPaths isAscending:ascending];
}

- (void)descendingSort{
    [self _ascendingSort:NO];
}


- (void)ascendingSort{
    [self _ascendingSort:YES];
}

- (void)recountSize{
    _machOSize = 0;
    _carSize = 0;
    _nibSize = 0;
    _pngSize = 0;
    _jpgSize = 0;
    _jsonSize = 0;
    _plistSize = 0;
    _otherSize = 0;
    _totalSize = 0;
    _frameworkSize = 0;
    _bundleSize = 0;
    _pluginSize = 0;
    [self machOSize];
    [self carSize];
    [self nibSize];
    [self pngSize];
    [self jpgSize];
    [self jsonSize];
    [self plistSize];
    [self otherSize];
    [self frameworkSize];
    [self bundleSize];
    [self pluginSize];
    [self totalSize];
    for (ASBaseDirectory * directory in self.allDirectories) {
        [directory recountSize];
    }
}

- (void)addFile:(ASBaseFile *)file{
    if ([file isKindOfClass:[ASMachOFile class]]) {
        [self.machOFiles addObject:file];
        _machOSize += file.inputSize;
    }else if ([file isKindOfClass:[ASCarFile class]]) {
        [self.carFiles addObject:file];
        _carSize += file.inputSize;
    }else if ([file isKindOfClass:[ASImageFile class]]) {
        if ([file.fileType isEqualToString:@"png"]) {
            [self.pngFiles addObject:file];
            _pngSize += file.inputSize;
        }else if ([file.fileType isEqualToString:@"jpg"]){
            [self.jpgFiles addObject:file];
            _pngSize += file.inputSize;
        }else if ([file.fileType isEqualToString:@"jpeg"]){
            [self.jpgFiles addObject:file];
            _jpgSize += file.inputSize;
        }
    }else if ([file isKindOfClass:[ASNibFile class]]) {
        [self.nibFiles addObject:file];
        _nibSize += file.inputSize;
    }else if ([file isKindOfClass:[ASBaseFile class]]) {
        if ([file.fileType isEqualToString:@"json"]) {
            [self.jsonFiles addObject:file];
            _jsonSize += file.inputSize;
        }else if ([file.fileType isEqualToString:@"plist"]){
            [self.plistFlies addObject:file];
            _plistSize += file.inputSize;
        }else{
            [self.otherFiles addObject:file];
            _otherSize += file.inputSize;
        }
    }
    
    [self.allFiles addObject:file];
    _totalSize += file.inputSize;
}

- (void)addDirectory:(ASBaseDirectory *)directory{
    if ([directory isKindOfClass:[ASNibDirectory class]]) {
        [self.nibs addObject:directory];
    }else if ([directory isKindOfClass:[ASPlugIn class]]) {
        [self.plugIns addObject:directory];
        _pluginSize += directory.all.totalSize;
    }else if ([directory isKindOfClass:[ASFramework class]]) {
        [self.frameworks addObject:directory];
        _frameworkSize += directory.all.totalSize;
    }else if ([directory isKindOfClass:[ASBundle class]]) {
        [self.bundles addObject:directory];
        _bundleSize += directory.all.totalSize;
    }else{
        [self.otherDirectories addObject:directory];
    }
    [self.allDirectories addObject:directory];
    [self.allDirectoryPaths addObject:directory.directoryPath];
}


@end
