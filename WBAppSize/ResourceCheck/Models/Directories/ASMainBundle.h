//
//  ASMainBundle.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBundle.h"
#import "ASMachOFile.h"

@interface ASMainBundle : ASBundle
@property (nonatomic, strong) NSString * appPath;
@property (nonatomic, strong) ASMachOFile * exeFile;

@end
