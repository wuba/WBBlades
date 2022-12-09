//
//  ASCarFile.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASCarFile.h"
#import "CarUnziper.h"
#import "ASFileManager.h"
#import "WBBladesCMD.h"
#import "ASImageFile.h"
#include <CommonCrypto/CommonDigest.h>
#import "NSString+ASUtils.h"
#import "ASUtils.h"

NSString * kASCarFileNotificationUserInfoUpdateTypeKey = @"kASCarFileNotificationUserInfoUpdateTypeKey";
NSString * kASCarFileUpdateTypeImages = @"kASCarFileUpdateTypeImages";

dispatch_queue_t _car_unzip_queue_t;

@interface ASCarFile ()
@property (nonatomic, strong) NSMutableArray * callBacks;
@property (nonatomic, assign) BOOL isLoading;
@end

@implementation ASCarFile

+ (void)load{
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASCarFile class]) withFileType:@"car"];
    
    _car_unzip_queue_t = dispatch_queue_create("ASCarFile_Unzip", DISPATCH_QUEUE_SERIAL);
}

static NSData * cmd(NSString *cmd) {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];  // Start task
    [task launch];
    NSData *data = [file readDataToEndOfFile];    // Get execution results.
    return data;
}

- (void)unzipCarFile:(ASCarFileBlock)callBack{
    NSAssert([NSThread isMainThread], @"请在主线程中发起图片信息的解压操作");
    if (self.hasLoaded) {
        callBack();
        return;
    }
    [self.callBacks addObject:callBack];
    if (self.isLoading) {
        return;
    }
    self.isLoading = YES;
    __block NSArray * images;
    dispatch_async(_car_unzip_queue_t, ^{
        NSString * outputPath = [self carCachePath];
        NSFileManager * fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:outputPath error:nil];
        BOOL isDirectory;
        if (![fm fileExistsAtPath:outputPath isDirectory:&isDirectory]) {
            [fm createDirectoryAtPath:outputPath withIntermediateDirectories:YES attributes:nil error:nil];
        }
        NSString * assets_thin = [NSString stringWithFormat:@"%@/Assets_thin1.car",outputPath];
        cmd([NSString stringWithFormat:@"assetutil --idiom phone --subtype 570 --scale 3 --display-gamut srgb --graphicsclass MTL2,2 --graphicsclassfallbacks MTL1,2:GLES2,0 --memory 1 --hostedidioms car,phone --deployment-target 13.0 %@ -o %@",self.filePath,assets_thin]);
        self.strippedSize = [ASUtils bytesSizeForFile:assets_thin];
        NSData * data = cmd([NSString stringWithFormat:@"assetutil -I %@",assets_thin]);
        NSArray * assetInfos = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSMutableDictionary * imgInfos = [NSMutableDictionary dictionary];
        for (NSDictionary * assetInfo in assetInfos) {
            NSString * assetType = assetInfo[AssetTypeKey];
            NSString * assetName = [ASImageFile nameByRemoveImgExtra:assetInfo[AssetNameKey]];
            if (!assetType||(![assetType isEqualToString:@"Image"])) {
                continue;
            }
            NSNumber * assetScale = assetInfo[AssetScaleKey];
            NSString * scaleExtra = [NSString stringWithFormat:@"@%@x",assetScale];
            if (![assetName hasSuffix:scaleExtra]&&[assetScale intValue]>1) {
                assetName = [assetName stringByAppendingString:scaleExtra];
            }
            [imgInfos setObject:assetInfo forKey:[NSString stringWithFormat:@"%@",assetName]];
        }
        __weak ASCarFile * weakSelf = self;
        [CarUnziper exportWithCarPath:assets_thin withOutPutPath:outputPath assetInfos: imgInfos fileNameSHA256InfoCallBack:^(NSDictionary *fileNameSHA256Info) {
            //SHA256文件名转换
            weakSelf.fileNameSHA256Info = fileNameSHA256Info;
            images = [ASFileManager imageFileMoreThanSize:0 fromPath:outputPath];
            for (ASImageFile * imageFile in images) {
                imageFile.car_isCarFile = YES;
                NSString * sha256key = [ASImageFile nameByRemoveImgExtra:imageFile.fileName];
                NSString * originFileName = fileNameSHA256Info[sha256key];
                if (originFileName) {
                    imageFile.fileName = originFileName;
                }
                imageFile.bundleName = self.bundleName;
                imageFile.frameworkName = self.frameworkName;
                imageFile.car_fileNameSHA256 = sha256key;
                NSString * assetName = [ASImageFile nameByRemoveImgExtra:imageFile.fileName];
                NSDictionary * assetInfo = imgInfos[assetName];
                if (![assetInfo isKindOfClass:[NSDictionary class]]) {
                    continue;
                }
                NSNumber * assetSize = assetInfo[AssetSizeKey];
                if ([assetSize respondsToSelector:@selector(unsignedLongValue)]) {
                    imageFile.car_size = [assetSize unsignedLongValue];
                }else{
                    imageFile.car_size = 0;
                }
                NSNumber * assetScale = assetInfo[AssetScaleKey];
                if ([assetSize respondsToSelector:@selector(doubleValue)]) {
                    imageFile.car_scale = [assetScale doubleValue];
                }else{
                    imageFile.car_scale = 1.0;
                }
                imageFile.car_name = assetInfo[AssetNameKey];
                imageFile.car_assetType = assetInfo[AssetTypeKey];
                imageFile.car_idiom = assetInfo[AssetIdiomKey]?:@"universal";
                imageFile.car_deploymentTarget = assetInfo[@"DeploymentTarget"];
                [imgInfos removeObjectForKey:assetName];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                weakSelf.isLoading = NO;
                if ([images isKindOfClass:[NSArray class]]) {
                    [weakSelf.images addObjectsFromArray:images];
                }
                [weakSelf countSize];
                [weakSelf finishCallBack];
                [self postDataUpdateNotificationUserInfo:@{kASCarFileNotificationUserInfoUpdateTypeKey:kASCarFileUpdateTypeImages}];
            });
        }];
    });
}

+ (NSURL * )carUnzipDirectoryPath{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@unzip_assets/",[ASUtils cachePathURL]]];
}

- (NSString *)carCachePath {
    return [NSString stringWithFormat:@"%@/%@",[[ASCarFile carUnzipDirectoryPath] path],[self.filePath as_sha256Value]];
}

- (void)finishCallBack{
    for (ASCarFileBlock callBack in self.callBacks) {
        self.hasLoaded = YES;
        callBack();
    }
    [self.callBacks removeAllObjects];
}

+ (instancetype)fileWithPath:(NSString *)filePath{
    ASCarFile * car = [super fileWithPath:filePath];
    car.hasLoaded = NO;
    return car;
}

- (NSMutableArray *)images{
    if (!_images) {
        _images = [NSMutableArray array];
    }
    return _images;
}

- (NSUInteger)imageSize{
    if (_imageSize!=0) {
        return _imageSize;
    }
    for (ASImageFile * file in self.images) {
        _imageSize += file.car_size;
    }
    return _imageSize;
}

- (NSMutableArray *)callBacks{
    if (!_callBacks) {
        _callBacks = [NSMutableArray array];
    }
    return _callBacks;
}


- (void)countSize{
    [self imageSize];
}

@end
