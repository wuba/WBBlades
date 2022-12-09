//
//  ASNibDirectory.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseDirectory.h"

@interface ASNibDirectory : ASBaseDirectory
@property (nonatomic, strong) NSMutableArray * nibs;
@property (nonatomic, assign) NSUInteger nibSize;
@end
