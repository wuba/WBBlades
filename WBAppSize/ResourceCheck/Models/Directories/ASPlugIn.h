//
//  ASPlugIn.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseDirectory.h"
#import "ASMachOFile.h"
@interface ASPlugIn : ASBaseDirectory
@property (nonatomic, strong) ASMachOFile * exeFile;
@end
