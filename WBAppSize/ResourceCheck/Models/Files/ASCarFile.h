//
//  ASCarFile.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASBaseFile.h"
@class ASImageFile;
typedef void(^ASCarFileBlock)(void);

extern NSString * kASCarFileNotificationUserInfoUpdateTypeKey;
extern NSString * kASCarFileUpdateTypeImages;

@interface ASCarFile : ASBaseFile

@property (nonatomic, assign) BOOL hasLoaded;
@property (nonatomic, assign) NSUInteger strippedSize;
@property (nonatomic, assign) NSUInteger imageSize;
@property (nonatomic, strong) NSMutableArray <ASImageFile *> * images;
@property (nonatomic, copy) NSDictionary * fileNameSHA256Info;
#pragma mark - DataUpdate

- (void)unzipCarFile:(ASCarFileBlock)callBack;

@end
