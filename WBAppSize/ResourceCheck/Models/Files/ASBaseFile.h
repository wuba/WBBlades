//
//  ASBaseFile.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, ASFileUsingState) {
    ASFileUsingUnKnow   = 0,
    ASFileUsingYES        = 1,
    ASFileUsingNO      = 2,
};

extern NSString * kASFileUpdateNotification;

@interface ASBaseFile : NSObject

@property (nonatomic, assign) ASFileUsingState usingState;

@property (nonatomic, assign) NSUInteger inputSize;
@property (nonatomic, strong) NSString * filePath;
@property (nonatomic, strong) NSString * bundleName;
@property (nonatomic, strong, readonly) NSString * inBundlePath;
@property (nonatomic, strong) NSString * frameworkName;
@property (nonatomic, strong) NSString * fileName;
@property (nonatomic, strong) NSString * fileType;
@property (nonatomic, strong) NSArray * usingNames;

@property (nonatomic, assign) BOOL isInCarFile;

+ (instancetype )fileWithPath:(NSString *)filePath;

+ (BOOL)checkFileTypeByPath:(NSString *)filePath;

- (NSArray *)mayUsingNames;

- (NSArray *)addtionUsingNames;

- (instancetype)initWithFilePath:(NSString *)filePath;
- (void)postDataUpdateNotification;
- (void)postDataUpdateNotificationUserInfo:(NSDictionary *)userInfo;
@end
