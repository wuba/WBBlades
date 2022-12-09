//
//  ASImageFile.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>
#import "ASBaseFile.h"


extern NSString * AssetTypeKey;
extern NSString * AssetSizeKey;
extern NSString * AssetScaleKey;
extern NSString * AssetNameKey;
extern NSString * AssetIdiomKey;

@interface ASImageFile : ASBaseFile


@property (nonatomic, assign) NSUInteger car_size;
@property (nonatomic, assign) NSUInteger car_scale;
@property (nonatomic, strong) NSString * car_fileNameSHA256;
@property (nonatomic, strong) NSString * car_assetType;
@property (nonatomic, strong) NSString * car_idiom;
@property (nonatomic, strong) NSString * car_name;
@property (nonatomic, strong) NSString * car_deploymentTarget;
@property (nonatomic, assign) BOOL car_isCarFile;
#pragma mark - DataUpdate

#pragma mark - TinyPng
@property (nonatomic, strong) NSString * url;
//@property (nonatomic, assign) NSInteger height;
//@property (nonatomic, assign) NSInteger width;

+ (BOOL)isImageFile:(NSString *)filePath;

+ (NSString *)nameByRemoveImgExtra:(NSString*)fileName;

@end

