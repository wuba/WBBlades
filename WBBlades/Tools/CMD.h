//
//  CMD.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/25.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>


//在控制台彩色打印
void colorPrint(NSString *info);

//剥离符号表
void stripFile(NSString *filePath);

//对文件进行拷贝
void copyFile(NSString *filePath);

//删除拷贝文件
void removeCopyFile(NSString *filePath);

//架构剥离，保留目标架构：arm64
void thinFile(NSString *filePath);

//对xcassert资源进行编译
void compileXcassets(NSString *path);

//删除文件
void removeFile(NSString *filePath);
