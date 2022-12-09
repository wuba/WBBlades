//
//  ASMachOFile.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseFile.h"

@interface ASMachOFile : ASBaseFile

@property (nonatomic, strong) NSMutableDictionary * mainSegmentInfo;

+ (BOOL)isMachOFile:(NSString *)filePath;


- (NSString *)mainSegmentSizeDiscription;
@end
