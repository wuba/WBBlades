//
//  ASImageFile.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/7.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASImageFile.h"
#import "ASFileManager.h"

//typedef void(^ASImageZipOptimizeBlock)();

NSString * AssetTypeKey = @"AssetType";
NSString * AssetSizeKey = @"SizeOnDisk";
NSString * AssetScaleKey = @"Scale";
NSString * AssetNameKey = @"Name";
NSString * AssetIdiomKey = @"Idiom";

typedef void(^ASImageFileCallBack)(BOOL,NSString *);

@interface ASImageFile ()

@end

@implementation ASImageFile

+ (void)load{
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASImageFile class]) withFileType:@"jpg"];
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASImageFile class]) withFileType:@"jpeg"];
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASImageFile class]) withFileType:@"png"];
}

+ (dispatch_queue_t)imageOptimizedQueue{
    static dispatch_queue_t serialQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        serialQueue = dispatch_queue_create("ASImageFile", DISPATCH_QUEUE_SERIAL);
    });
    return serialQueue;
}

+ (BOOL)isImageFile:(NSString *)filePath{
    return ([filePath hasSuffix: @".png"]||[filePath hasSuffix: @".jpg"]);
}

- (NSArray *)addtionUsingNames{
    NSString * fileName = self.fileName;
    NSMutableArray * usingNames = [NSMutableArray array];
    [usingNames addObjectsFromArray:[self aliasByPic:fileName]];
    return usingNames;
}

- (NSArray *)aliasByPic:(NSString *)fileName{
    NSMutableArray * usingNames = [NSMutableArray array];
    NSString * usingName0 = fileName;
//    [usingNames addObject:usingName0];
    NSMutableArray * nameParts = [[fileName componentsSeparatedByString:@"."] mutableCopy];
    NSString * suffix = @"";
    if (nameParts.count>1) {
        suffix = [nameParts lastObject];
    }
    [nameParts removeLastObject];
    NSString * usingName1 = [nameParts componentsJoinedByString:@"."];
//    [usingNames addObject:usingName1];

    NSString * usingName2 = usingName1;
    if ([usingName2 hasSuffix:@"@2x"]||[usingName1 hasSuffix:@"@3x"]) {
        usingName2 = [usingName2 substringToIndex:usingName2.length-3];
        [usingNames addObject:usingName2];
        NSString * usingName3 = [NSString stringWithFormat:@"%@.%@",usingName2,suffix];
        [usingNames addObject:usingName3];
    }
    if ([fileName containsString:@"/"]) {
        [usingNames addObjectsFromArray: [self aliasByPic:[fileName lastPathComponent]]];
    }
    return usingNames;
}




+ (NSString *) nameByRemoveImgExtra:(NSString*)fileName{
    fileName = [fileName stringByReplacingOccurrencesOfString:@".png" withString:@""];
    fileName = [fileName stringByReplacingOccurrencesOfString:@".jpg" withString:@""];
    fileName = [fileName stringByReplacingOccurrencesOfString:@".jpeg" withString:@""];
    fileName = [fileName stringByReplacingOccurrencesOfString:@".gif" withString:@""];
    fileName = [fileName stringByReplacingOccurrencesOfString:@".webp" withString:@""];
    return fileName;
}


@end
