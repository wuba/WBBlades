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
void colorPrint(NSString *info);
const char *cmd(NSString *cmd);
bool isResource(NSString *type);
void enumAllFiles(NSString *path);
void enumPodFiles(NSString *path);

unsigned long long resourceSize = 0;
unsigned long long codeSize = 0;
static NSDictionary *podResult;
static NSMutableSet *s_classSet;
static void scanStaticLibrary(int argc, const char * argv[]);
static void scanUnUseClass(int argc, const char * argv[]);
int main(int argc, const char * argv[]) {
    @autoreleasepool {
//    NSData *fileData = [WBBladesFileManager readFromFile:@"/Users/a58/Library/Developer/Xcode/DerivedData/HelloWorld-gygobitexxxrzsfnedhacdluklxc/Build/Products/Debug-iphoneos/HelloWorld.app/HelloWorld"];
    
        NSData *fileData = [WBBladesFileManager readFromFile:@"/Volumes/pliaf/8.22.5/Payload/58tongcheng.app/58tongcheng_arm64"];
//        NSData *fileData = [WBBladesFileManager readFromFile:@"/Users/a58/Desktop/WinSFA"];
        [WBBladesScanManager scanAllClassWithFileData:fileData classes:nil];
        //静态库体积分析参数 1 + 路径
        //无用类扫描 2 + APP可执行文件路径 + pod 静态库 + pod 静态库

        NSString *type = [NSString stringWithFormat:@"%s",argv[1]];
        if ([type isEqualToString:@"1"]) {
            scanStaticLibrary(argc, argv);
        }else if ([type isEqualToString:@"2"]){
            scanUnUseClass(argc, argv);
        }
    }
}
void scanStaticLibrary(int argc, const char * argv[]){
    NSString *podPath = [NSString stringWithFormat:@"%s",argv[2]];
    NSLog(@"Pod 路径：%@",podPath);
    NSString * podName = [podPath lastPathComponent];
    NSString * outPutPath = [[podPath stringByDeletingLastPathComponent] stringByDeletingLastPathComponent];
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesResult.plist"];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];
    NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
    podResult = [NSMutableDictionary dictionary];
    
    enumAllFiles(podPath);
    colorPrint([NSString stringWithFormat:@"codeSize = %llu KB\n resourceSize = %llu KB",codeSize/1024,resourceSize/1024]);
    
    [podResult setValue:[NSString stringWithFormat:@"%.1f MB",resourceSize/1024.0/1024] forKey:@"resource"];
    [podResult setValue:[NSString stringWithFormat:@"%.1f MB",(codeSize+resourceSize)/1024.0/1024] forKey:@"total"];
    [resultData setValue:podResult forKey:podName];
    [resultData writeToFile:outPutPath atomically:YES];
}

void scanUnUseClass(int argc, const char * argv[]){
    s_classSet = [NSMutableSet set];
    NSString *podName = @"";
    for (int i = 0; i < argc - 3; i++) {
        NSString *podPath = [NSString stringWithFormat:@"%s",argv[i+3]];
        NSLog(@"读取%@所有类",podPath);
        enumPodFiles(podPath);
        NSString * tmp = [podPath lastPathComponent];
        if (i != 0) {
            tmp = [@"+" stringByAppendingString:tmp];
        }
        podName = [podName stringByAppendingString:tmp];
        
    }
    NSString *appPath = [NSString stringWithFormat:@"%s",argv[2]];
    
    if (![[[[appPath lastPathComponent] componentsSeparatedByString:@"."] lastObject] isEqualToString:@"app"]) {
        NSLog(@"请在第二个参数输入app文件");
        return;
    }
    NSLog(@"正在扫描 %@",appPath);
    
    NSString *appName = [[[appPath lastPathComponent] componentsSeparatedByString:@"."] firstObject];
    appPath = [appPath stringByAppendingPathComponent:appName];
    
    NSSet *classset = [WBBladesScanManager scanAllClassWithFileData:[WBBladesFileManager readFromFile:appPath] classes:s_classSet];
    
    NSString * outPutPath = [[appPath stringByDeletingLastPathComponent] stringByDeletingLastPathComponent];
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




void handleStaticLibrary(NSString *filePath){
    //获取静态库名字
    NSString *name = [filePath lastPathComponent];
    NSLog(@"尝试分析文件---%@",name);
    
    //拷贝文件
    NSLog(@"正在备份文件...");
    NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@_copy",filePath];
    NSString *cpCmd = [NSString stringWithFormat:@"cp -f %@ %@_copy",filePath,filePath];
    cmd(rmCmd);
    cmd(cpCmd);
    
    //文件架构拆分
    NSLog(@"正在进行架构拆分...");
    NSString *thinCmd = [NSString stringWithFormat:@"lipo %@_copy -thin arm64  -output %@_copy",filePath,filePath];
    cmd(thinCmd);

    //去除bitcode信息
    NSLog(@"正在去除bitcode中间码...");
    NSString *bitcodeCmd = [NSString stringWithFormat:@"xcrun bitcode_strip -r %@_copy -o %@_copy",filePath,filePath];
    cmd(bitcodeCmd);
    //剥离符号表
    NSLog(@"正在剥离符号表...");
    NSString *stripCmd = [NSString stringWithFormat:@"xcrun strip -x %@_copy",filePath];
    cmd(stripCmd);
    
    //读取mach-o文件
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
    unsigned long long size = [WBBladesScanManager scanStaticLibrary:fileData];
    codeSize += size;
    //暂时不考虑多静态库链接问题
    [[WBBladesLinkManager shareInstance] clearLinker];
    //删除临时文件
    cmd(rmCmd);
    colorPrint([NSString stringWithFormat:@"%@ 链接后大小 %llu 字节",name,size]);
    if (size>0) {
        [podResult setValue:[NSString stringWithFormat:@"%.1f MB",size/1024.0/1024] forKey:name];
    }
}

void handleStaticLibraryForClassList(NSString *filePath){
    
    @autoreleasepool {
        //拷贝文件
        NSLog(@"正在备份文件...");
        NSString *rmCmd = [NSString stringWithFormat:@"rm -rf %@_copy",filePath];
        NSString *cpCmd = [NSString stringWithFormat:@"cp -f %@ %@_copy",filePath,filePath];
        cmd(rmCmd);
        cmd(cpCmd);
        
        //文件架构拆分
        NSString *thinCmd = [NSString stringWithFormat:@"lipo %@_copy -thin arm64  -output %@_copy",filePath,filePath];
        cmd(thinCmd);
        
        //读取mach-o文件
        NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
        NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
        
        NSSet *classSet = [WBBladesScanManager scanStaticLibraryForClassList:fileData];
        s_classSet = [[s_classSet setByAddingObjectsFromSet:classSet] mutableCopy];
        //删除临时文件
        cmd(rmCmd);
    }
}


void enumPodFiles(NSString *path){
    
    //遍历单一pod
    NSFileManager * fileManger = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
    NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
    
    if (isExist && !symbolicLink) {
        if (isDir) {
            
            if ([[[[path lastPathComponent] componentsSeparatedByString:@"."] lastObject] isEqualToString:@"xcassets"]) {
                
                return;
            }else if ([[[[path lastPathComponent] componentsSeparatedByString:@"."] lastObject] isEqualToString:@"git"] ||
                      [[[path lastPathComponent] lowercaseString] isEqualToString:@"demo"] ||
                      [[[path lastPathComponent] lowercaseString] isEqualToString:@"document"]
                      ){
                //忽略文档、demo、git 目录
                return;
            }else{
                NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
                NSString * subPath = nil;
                for (NSString * str in dirArray) {
                    subPath  = [path stringByAppendingPathComponent:str];
                    BOOL issubDir = NO;
                    [fileManger fileExistsAtPath:subPath isDirectory:&issubDir];
                    enumPodFiles(subPath);
                }
            }
        }else{
            NSString *fileName = [path lastPathComponent];
            
            //判断是否为资源
            NSArray *array = [[fileName lowercaseString] componentsSeparatedByString:@"."];
            NSString *fileType = [array lastObject];
            if (isResource(fileType)) {
                
            }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//静态库文件
                handleStaticLibraryForClassList(path);
            }else{//大概率是编译产生的中间文件
            }
        }
    }
}

void enumAllFiles(NSString *path){
    //遍历单一pod
    NSFileManager * fileManger = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
    NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
   
    if (isExist && !symbolicLink) {
        if (isDir) {
            
            if ([[[[path lastPathComponent] componentsSeparatedByString:@"."] lastObject] isEqualToString:@"xcassets"]) {
                
                //进行xcassets 编译
                NSString *complieCmd = [NSString stringWithFormat:@"actool   --compress-pngs --enable-on-demand-resources YES --filter-for-device-model iPhone9,2 --filter-for-device-os-version 12.2  --target-device iphone --target-device ipad --minimum-deployment-target 11 --platform iphoneos --product-type com.apple.product-type.application --compile %@ %@",[path stringByDeletingLastPathComponent],path];
                cmd(complieCmd);
                NSData *fileData = [WBBladesFileManager  readFromFile:[NSString stringWithFormat:@"%@/Assets.car",[path stringByDeletingLastPathComponent]]];
                NSLog(@"资源编译后 %@大小：%lu 字节",[path lastPathComponent],[fileData length]);
                resourceSize += [fileData length];
                cmd([NSString stringWithFormat:@"rm -rf %@/Assets.car",[path stringByDeletingLastPathComponent]]);
            }else if ([[[[path lastPathComponent] componentsSeparatedByString:@"."] lastObject] isEqualToString:@"git"] ||
                      [[[path lastPathComponent] lowercaseString] isEqualToString:@"demo"] ||
                      [[[path lastPathComponent] lowercaseString] isEqualToString:@"document"]
                      ){
                //忽略文档、demo、git 目录
                return;
            }else{
                NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
                NSString * subPath = nil;
                for (NSString * str in dirArray) {
                    subPath  = [path stringByAppendingPathComponent:str];
                    BOOL issubDir = NO;
                    [fileManger fileExistsAtPath:subPath isDirectory:&issubDir];
                    enumAllFiles(subPath);
                }
            }
        }else{
            NSString *fileName = [path lastPathComponent];
            
            //判断是否为资源
            NSArray *array = [[fileName lowercaseString] componentsSeparatedByString:@"."];
            NSString *fileType = [array lastObject];
            if (isResource(fileType)) {
                //统计资源文件大小
                NSData *fileData = [WBBladesFileManager  readFromFile:path];
                NSLog(@"资源 %@大小：%lu 字节",fileName,[fileData length]);
                resourceSize += [fileData length];
                
            }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//静态库文件
                handleStaticLibrary(path);
            }else{//大概率是编译产生的中间文件
            }
        }
    }
}

bool isResource(NSString *type){
    
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


const char *cmd(NSString *cmd){
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    // 开始task
    NSFileHandle *file = [pipe fileHandleForReading];
    [task launch];
    
    // 获取运行结果
    NSData *data = [file readDataToEndOfFile];
    return [data bytes];
}

void colorPrint(NSString *info){
    
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: @"/bin/bash"];
    NSString *cmd = [NSString stringWithFormat:@"echo -e '\e[1;36m %@ \e[0m'",info];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", cmd, nil];
    [task setArguments: arguments];
   
    [task launch];
}

