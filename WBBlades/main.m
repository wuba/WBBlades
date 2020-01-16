//
//  main.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WBBladesFileManager.h"
#import "WBBladesScanManager.h"
#import "WBBladesLinkManager.h"
#import "WBBladesScanManager+UnuseClassScan.h"
#import "WBBladesScanManager+CrashSymbol.h"
#import "CMD.h"

typedef NS_ENUM(NSInteger, WBBladesType) {
    WBBladesTypeStaticLibSize    = 1,
    WBBladesTypeUnusedClass      = 2,
    WBBladesTypeCrashLog         = 3,
};

static BOOL isResource(NSString *type);
static void enumAllFiles(NSString *path);
static void enumPodFiles(NSString *path);

static unsigned long long resourceSize = 0;
static unsigned long long codeSize = 0;

static NSDictionary *podResult;
static NSMutableSet *s_classSet;
static void scanStaticLibrary(int argc, const char * argv[]);
static void scanUnUseClass(int argc, const char * argv[]);
static void scanCrashSymbol(int argc, const char * argv[]);
static NSString *resultFilePath(void);

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        //静态库体积分析参数 1 + 路径
        //无用类扫描 2 + APP可执行文件路径 + pod 静态库 + pod 静态库
        //crash日志解析 3 + APP可执行文件路径 + 崩溃偏移地址（以逗号为分割）
        NSInteger type = [[NSString stringWithFormat:@"%s",argv[1]] integerValue];
        if (type == WBBladesTypeStaticLibSize) {
            //进行静态库体积分析
            scanStaticLibrary(argc, argv);
        }else if (type == WBBladesTypeUnusedClass){
            //进行无用类检测
            scanUnUseClass(argc, argv);
        }else if(type == WBBladesTypeCrashLog){
            //进行crash日志解析
            scanCrashSymbol(argc, argv);
        }
    }
}

#pragma mark Scan Function
static void scanStaticLibrary(int argc, const char * argv[]) {
    
    //参数1 为个数，参数2 为pod 路径列表
    for (int i = 0; i < argc - 2; i++) {
        @autoreleasepool {
            //获取每个pod的路径
            NSString *podPath = [NSString stringWithFormat:@"%s",argv[i+2]];
            NSLog(@"Pod 路径：%@", podPath);
            
            //获取pod 名称
            NSString *podName = [podPath lastPathComponent];
            
            //获取结果文件输出路径
            NSString *outPutPath = resultFilePath();
            outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesResult.plist"];
            
            //获取上次分析结果
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];
            NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
            podResult = [NSMutableDictionary dictionary];
            
            //资源和代码体积清空
            resourceSize = 0;
            codeSize = 0;
            
            //递归遍历pod中的每个文件
            enumAllFiles(podPath);
            
            //打印当前pod资源和代码大小
            colorPrint([NSString stringWithFormat:@"codeSize = %llu KB\n resourceSize = %llu KB", codeSize/1024,resourceSize/1024]);
            
            //将结果写入文件
            [podResult setValue:[NSString stringWithFormat:@"%.2f MB",resourceSize/1024.0/1024] forKey:@"resource"];
            [podResult setValue:[NSString stringWithFormat:@"%.2f MB", (codeSize + resourceSize) / 1024.0 / 1024] forKey:@"total"];
            [resultData setValue:podResult forKey:podName];
            [resultData writeToFile:outPutPath atomically:YES];
        }
    }
}

static void scanUnUseClass(int argc, const char * argv[]) {
    s_classSet = [NSMutableSet set];
    NSString *podName = @"";
    
    if (argc < 3) {
        NSLog(@"参数不足");
        return;
    }
    //遍历输入的pod，提取所有pod中的类
    for (int i = 3; i < argc; i++) {
        @autoreleasepool {
            NSString *podPath = [NSString stringWithFormat:@"%s",argv[i]];
            NSLog(@"读取%@所有类", podPath);
            enumPodFiles(podPath);
            NSString *tmp = [podPath lastPathComponent];
            if (i != 0) {
                tmp = [@"+" stringByAppendingString:tmp];
            }
            podName = [podName stringByAppendingString:tmp];
        }
    }
    NSString *appPath = [NSString stringWithFormat:@"%s",argv[2]];
    
    //读取二进制文件，对输入的pod下的类进行无用类扫描
    NSSet *classset = [WBBladesScanManager scanAllClassWithFileData:[WBBladesFileManager readArm64FromFile:appPath] classes:s_classSet];
    
    //输出数据
    NSString *outPutPath = resultFilePath();
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesClass.plist"];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];
    NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
    NSMutableArray *classes = [NSMutableArray array];
    [classset enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        [classes addObject:obj];
    }];
    [resultData setObject:classes forKey:podName];
    [resultData writeToFile:outPutPath atomically:YES];
}

static void scanCrashSymbol(int argc, const char * argv[]) {
    NSString *appPath = [NSString stringWithFormat:@"%s", argv[2]];
    NSString *crashAddress = [NSString stringWithFormat:@"%s", argv[3]];
    
    NSDictionary *result = [WBBladesScanManager symbolizeWithMachOFile:[WBBladesFileManager readArm64FromFile:appPath] crashOffsets:crashAddress];
    //获取结果文件输出路径
    NSString *outPutPath = resultFilePath();
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesCrash.plist"];
    
    [result writeToFile:outPutPath atomically:YES];
}

#pragma mark Handle
void handleStaticLibrary(NSString *filePath) {
    //获取静态库名字
    NSString *name = [filePath lastPathComponent];
    NSLog(@"分析文件---%@", name);
    
    //拷贝文件
    removeCopyFile(filePath);
    copyFile(filePath);
    
    //文件架构拆分
    thinFile(filePath);
    
    //读取mach-o文件并统计体积
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
    unsigned long long size = [WBBladesScanManager scanStaticLibrary:fileData];
    NSLog(@"%@ 大小为 %.2f MB", name, (size) / 1024.0 / 1024.0);
    codeSize += size;
    
    //删除临时文件
    removeCopyFile(filePath);
    colorPrint([NSString stringWithFormat:@"%@ 链接后大小 %llu 字节", name, size]);
    if (size > 0) {
        [podResult setValue:[NSString stringWithFormat:@"%.2f MB",size / 1024.0 / 1024] forKey:name];
    }
}

void handleStaticLibraryForClassList(NSString *filePath) {
    
    @autoreleasepool {
        //拷贝文件
        NSLog(@"正在备份文件...");
        removeCopyFile(filePath);
        copyFile(filePath);
        
        //文件架构拆分
        thinFile(filePath);
        
        //读取mach-o文件
        NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
        NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
        
        NSSet *classSet = [WBBladesScanManager dumpClassList:fileData];
        s_classSet = [[s_classSet setByAddingObjectsFromSet:classSet] mutableCopy];
        //删除临时文件
        removeCopyFile(filePath);
    }
}

#pragma mark Enumurate Files
static void enumPodFiles(NSString *path) {
    
    //遍历单一pod
    NSFileManager *fileManger = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
    NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
    
    if(!isExist || symbolicLink){
        return;
    }
    
    NSString *lastPathComponent = [path lastPathComponent];
    if (isDir) {
        if ([lastPathComponent hasSuffix:@"xcassets"] ||
            [lastPathComponent hasSuffix:@"git"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"demo"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"product"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"document"]) {
            //ignore resources,git,demo,product,document
            return;
        }else{
            NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
            NSString * subPath = nil;
            for (NSString * str in dirArray) {
                subPath  = [path stringByAppendingPathComponent:str];
                BOOL isSubDir = NO;
                [fileManger fileExistsAtPath:subPath isDirectory:&isSubDir];
                enumPodFiles(subPath);
            }
        }
    }else{
        //判断是否为资源
        NSArray *array = [[lastPathComponent lowercaseString] componentsSeparatedByString:@"."];
        NSString *fileType = [array lastObject];
        if (isResource(fileType)) {
            
        }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//静态库文件
            handleStaticLibraryForClassList(path);
        }else{//大概率是编译产生的中间文件
        }
    }
}

static void enumAllFiles(NSString *path) {
    @autoreleasepool {
        //遍历单一pod
        NSFileManager * fileManger = [NSFileManager defaultManager];
        BOOL isDir = NO;
        BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
        NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
        
        if (!isExist || symbolicLink) {//如果不存在或是软连接
            return;
        }
        
        NSString *lastPathComponent = [path lastPathComponent];
        if (isDir) {//如果是路径
            if ([lastPathComponent hasSuffix:@"xcassets"]) {//如果是xcassets资源
                //进行xcassets 编译
                compileXcassets(path);
                    
                //获取编译后的.car文件的大小并统计
                NSData *fileData = [WBBladesFileManager  readFromFile:[NSString stringWithFormat:@"%@/Assets.car",[path stringByDeletingLastPathComponent]]];
                NSLog(@"资源编译后 %@大小：%lu 字节",[path lastPathComponent],[fileData length]);
                resourceSize += [fileData length];
                    
                //删除编译后的.car文件
                removeFile(path);
            }else if ([lastPathComponent hasSuffix:@"git"] ||
                      [[lastPathComponent lowercaseString] isEqualToString:@"demo"] ||
                      [[lastPathComponent lowercaseString] isEqualToString:@"document"]){
                //ignore git,demo,document
                return;
            }else{
                NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
                NSString * subPath = nil;
                //递归遍历当前文件夹内所有文件
                for (NSString * str in dirArray) {
                    subPath  = [path stringByAppendingPathComponent:str];
                    BOOL issubDir = NO;
                    [fileManger fileExistsAtPath:subPath isDirectory:&issubDir];
                    enumAllFiles(subPath);
                }
            }
        }else{
            //判断是否为资源
            NSArray *array = [[lastPathComponent lowercaseString] componentsSeparatedByString:@"."];
            NSString *fileType = [array lastObject];
                
            //只统计在资源列表内的资源
            if (isResource(fileType)) {
                //统计资源文件大小
                NSData *fileData = [WBBladesFileManager  readFromFile:path];
//               NSLog(@"资源 %@大小：%lu 字节",fileName,[fileData length]);
                resourceSize += [fileData length];
            }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//静态库文件
                handleStaticLibrary(path);
            }else{//大概率是编译产生的中间文件
            }
        }
    }
}

#pragma mark Tools
//资源类型，如有特殊，请补充
static BOOL isResource(NSString *type) {
    
    if ([type isEqualToString:@"nib"] ||
        [type isEqualToString:@"plist"] ||
        [type isEqualToString:@"png"] ||
        [type isEqualToString:@"jpg"] ||
        [type isEqualToString:@"jpeg"] ||
        [type isEqualToString:@"pdf"] ||
        [type isEqualToString:@"bundle"] ||
        [type isEqualToString:@"json"] ||
        [type isEqualToString:@"js"] ||
        [type isEqualToString:@"db"] ||
        [type isEqualToString:@"mp3"] ||
        [type isEqualToString:@"mp4"] ||
        [type isEqualToString:@"htm"] ||
        [type isEqualToString:@"html"] ||
        [type isEqualToString:@"aiff"] ||
        [type isEqualToString:@"ttf"] ||
        [type isEqualToString:@"strings"]) {
        
        return YES;
    }
    
    return NO;
}

static NSString *resultFilePath() {
    // 文件保存的路径
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    return documentPath;
}
