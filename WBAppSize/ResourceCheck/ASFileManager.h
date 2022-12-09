//
//  ASFileManager.h
//  CarUnzip
//
//  Created by Shwnfee on 2022/1/17.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Cocoa/Cocoa.h>
#import "ASImageFile.h"
#import "ASMainBundle.h"
typedef void(^ASDownloadFinished)(NSString * savePath, NSImage * image);
typedef void(^ASDownloadProgress)(NSInteger receivedSize, NSInteger expectedSize);

@interface ASFileManager : NSObject

/**
 检测指定目录下的包资源信息结果
 参数1：appPath  指定需要检测App文件目录（.app文件）
 */
+ (ASMainBundle *)mainBundleWithAppPath:(NSString *)appPath;

/**
 检测bundle内未使用的图片
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 */
+ (NSArray<ASBaseFile *> *)checkUnusedPictureOfBundle:(ASMainBundle *)mainBundle;
/**
 检测默认类型文件使用情况
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 */
+ (NSArray<ASBaseFile *>*)checkUnusedAssetsOfBundleByDefault:(ASMainBundle *)mainBundle;
/**
 检测指定类型文件使用情况
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 */
+ (NSArray<ASBaseFile *>*)checkUnusedAssetsOfBundle:(ASMainBundle *)mainBundle withFileTypes:(NSArray <NSString *>*)fileTypes;

/**
 检测重复文件（异步）
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 参数2:  callBack 回调
 */
+ (void)duplicateFilesIn:(ASMainBundle *)mainBundle callBack:(void(^)(NSDictionary *))callBack;
/**
 检测重复文件（同步）
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 */
+ (NSDictionary *)duplicateFilesIn:(ASMainBundle *)mainBundle;

/**
 获取某目录下图片信息
 参数1：size 过滤图片数据大小小于该参数值的信息
 参数2:  path 目标路径
 */
+ (NSArray *)imageFileMoreThanSize:(NSUInteger)size fromPath:(NSString *)path;


#pragma mark - ToolMethods

/**
 解压出mainbudle内的.car图片资源文件
 参数1：mainBundle  需要检测的目标ASMainBundle实例对象
 */
+ (void)unzipCarAtMainBundle:(ASMainBundle *)mainBundle callBack:(void(^)(void))callBack;


#pragma mark - Dynamic File Info Model

/**
 获取ASFileManager单例
 */
+ (instancetype)shareInstance;
/**
 注册新的文件数据模型类型
 参数1：classString  数据类名称（要求为ASBaseFile子类）
 参数2：fileType  文件后缀（可以传空，然后配合子类实现- [ASBaseFile checkFileTypeByPath:] 方法来进一步确认文件类型）
 */
- (void)registerFileModelClassString:(NSString *)classString withFileType:(NSString *)fileType;
/**
 注册新的目录数据模型类型（要求为ASBaseDirectory子类）
 参数1：classString  数据类名称
 参数2：directoryType  文件后缀
 */
- (void)registerDirectoryModelClassString:(NSString *)classString withDirectoryType:(NSString *)directoryType;
/**
 根据地址创建新的文件数据模型类型
 参数1：filePath  文件地址
 */
- (ASBaseFile *)createFileModelByFilePath:(NSString *)filePath;
/**
 根据地址创建新的目录数据模型类型
 参数1：directoryPath  目录地址
 */
- (ASBaseDirectory *)createDirectoryModelByDirectoryPath:(NSString *)directoryPath;


@end
