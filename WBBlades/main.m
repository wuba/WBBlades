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
#import "WBBladesCMD.h"

static BOOL isResource(NSString *type);
static void enumAllFiles(NSString *path);
static void enumLibFiles(NSString *path);

static unsigned long long resourceSize = 0;
static unsigned long long codeSize = 0;

static NSDictionary *sizeResult;
static NSMutableSet *s_classSet;
static void scanStaticLibrary(int argc, const char * argv[]);
static void scanUnusedClass(int argc, const char * argv[]);
static void scanCrashSymbol(int argc, const char * argv[]);
static NSString *resultFilePath(void);

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        
        NSString *staticLibSizeStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"size"];
        NSString *unusedClassStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"unused"];
        NSString *crashLogStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"symbol"];

        if (staticLibSizeStr.length > 0) {
            scanStaticLibrary(argc, argv);//scan static library size
        }else if (unusedClassStr.length > 0){
            scanUnusedClass(argc, argv);//scan unused class
        }else if (crashLogStr.length > 0){
            scanCrashSymbol(argc, argv);//crash log symbolicate
        }else{
            NSLog(@"分析静态库的体积：WBBlades -size xxx.a xxx.framework ....");
            NSLog(@"分析无用类的体积：WBBlades -unused xxx.app -from xxx.a xxx.a ....(-from 标识只分析以下静态库中的无用类，不加此参数默认为APP中全部类)");
            NSLog(@"日志符号化：WBBlades -symbol xxx.app -logPath 1234,5678,91011");
        }
    }
}

#pragma mark Scan Function
static void scanStaticLibrary(int argc, const char * argv[]) {
    
    //param1:type  params2:libs' path list
    for (int i = 0; i < argc - 2; i++) {
        @autoreleasepool {
            NSString *libPath = [NSString stringWithFormat:@"%s",argv[i+2]];//each libs' path
            NSLog(@"分析路径：%@", libPath);
            
            NSString *libName = [libPath lastPathComponent];//lib's name
            
            NSString *outPutPath = resultFilePath();//result output path
            outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesResult.plist"];
            
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];//last result
            NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
            sizeResult = [NSMutableDictionary dictionary];
            
            resourceSize = 0;//empty the resources' size
            codeSize = 0;//empty the codes' size
            
            enumAllFiles(libPath);//enumerate all libs' files
            
            //color prints each lib's resources' size and code's sizes
            colorPrint([NSString stringWithFormat:@"codeSize = %llu KB\n resourceSize = %llu KB", codeSize/1024,resourceSize/1024]);
            
            //write results to file
            [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB",resourceSize/1024.0/1024] forKey:@"resource"];
            [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB", (codeSize + resourceSize) / 1024.0 / 1024] forKey:@"total"];
            [resultData setValue:sizeResult forKey:libName];
            [resultData writeToFile:outPutPath atomically:YES];
        }
    }
}

static void scanUnusedClass(int argc, const char * argv[]) {
    s_classSet = [NSMutableSet set];
    
    NSString *selectLibs = [[NSUserDefaults standardUserDefaults] stringForKey:@"from"];
    
    NSString *libName = @"";
    if (selectLibs.length > 0) {
        //enumerate all libs and all classes 
        for (int i = 4; i < argc; i++) {
            @autoreleasepool {
                NSString *libPath = [NSString stringWithFormat:@"%s",argv[i]];
                NSLog(@"读取%@所有类", libPath);
                enumLibFiles(libPath);
                NSString *tmp = [libPath lastPathComponent];
                tmp = [@" " stringByAppendingString:tmp];
                libName = [libName stringByAppendingString:tmp];
            }
        }
    }
    
    NSString *appPath = [[NSUserDefaults standardUserDefaults] stringForKey:@"unused"];
    
    //read binary files, scan all libs and classes to find unused classes
    NSSet *classset = [WBBladesScanManager scanAllClassWithFileData:[WBBladesFileManager readArm64FromFile:appPath] classes:s_classSet];
    
    //write results to file
    NSString *outPutPath = resultFilePath();
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesClass.plist"];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];
    NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
    NSMutableArray *classes = [NSMutableArray array];
    [classset enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        [classes addObject:obj];
    }];
    [resultData setObject:classes forKey:libName];
    [resultData writeToFile:outPutPath atomically:YES];
}

static void scanCrashSymbol(int argc, const char * argv[]) {
    NSString *appPath = [[NSUserDefaults standardUserDefaults] stringForKey:@"symbol"];
    NSString *crashLogPath = [[NSUserDefaults standardUserDefaults] stringForKey:@"logPath"];
    
    //从崩溃日志中获取所有与该进程相关的偏移地址
    NSArray *crashAddress = [WBBladesFileManager obtainAllCrashOffsets:crashLogPath appPath:appPath];
    
    //获取解析结果
    NSDictionary *result = [WBBladesScanManager symbolizeWithMachOFile:[WBBladesFileManager readArm64FromFile:appPath] crashOffsets:crashAddress];
    
    //生成崩溃解析后的完整日志
    NSString *outputLog = [WBBladesFileManager obtainOutputLogWithResult:result];
    
    //write results to file
    NSString *outPutPath = resultFilePath();
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesCrash.txt"];
    [outputLog writeToFile:outPutPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

#pragma mark Handle
void handleStaticLibrary(NSString *filePath) {
    
    NSString *name = [filePath lastPathComponent];//static library's name
    NSLog(@"分析文件---%@", name);
    
    removeCopyFile(filePath);//remove file
    copyFile(filePath);//copy file
    
    thinFile(filePath);//arm64 file
    stripFile(filePath);//strip file
    
    //read mach-o file and calculate size
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager readFromFile:copyPath];
    unsigned long long size = [WBBladesScanManager scanStaticLibrary:fileData];
    NSLog(@"%@ 大小为 %.2f MB", name, (size) / 1024.0 / 1024.0);
    codeSize += size;
    
    removeCopyFile(filePath);//remove tmp file
    colorPrint([NSString stringWithFormat:@"%@ 链接后大小 %llu 字节", name, size]);
    if (size > 0) {
        [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB",size / 1024.0 / 1024] forKey:name];
    }
}

void handleStaticLibraryForClassList(NSString *filePath) {
    
    @autoreleasepool {
        NSLog(@"正在备份文件...");
        removeCopyFile(filePath);//remove tmp file
        copyFile(filePath);//copy file
        
        thinFile(filePath);//arm64 file
        
        //read mach-o file
        NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
        NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
        
        NSSet *classSet = [WBBladesScanManager dumpClassList:fileData];
        s_classSet = [[s_classSet setByAddingObjectsFromSet:classSet] mutableCopy];

        removeCopyFile(filePath);//remove tmp file
    }
}

#pragma mark Enumerate Files
static void enumLibFiles(NSString *path) {
    
    //enumerate each lib
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
            [[lastPathComponent lowercaseString] hasSuffix:@"dsym"] ||
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
                enumLibFiles(subPath);
            }
        }
    }else{
        NSArray *array = [[lastPathComponent lowercaseString] componentsSeparatedByString:@"."];
        NSString *fileType = [array lastObject];
        //judge whether it is a resource
        if (isResource(fileType)) {

        }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//static library
            handleStaticLibraryForClassList(path);
        }else{//Probably it is a compiled intermediate files
        }
    }
}

static void enumAllFiles(NSString *path) {
    @autoreleasepool {
        //enumerate each lib
        NSFileManager * fileManger = [NSFileManager defaultManager];
        BOOL isDir = NO;
        BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
        NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
        
        if (!isExist || symbolicLink) {//not exist or a symbolic link
            return;
        }
        
        NSString *lastPathComponent = [path lastPathComponent];
        if (isDir) {////judge whether it is a path
            if ([lastPathComponent hasSuffix:@"xcassets"]) {////judge whether it is a resource
                compileXcassets(path);//compile xcassets
                    
                //compile '.car' type files to calculate size
                NSString *assetsCarPath = [NSString stringWithFormat:@"%@/Assets.car",[path stringByDeletingLastPathComponent]];
                NSData *fileData = [WBBladesFileManager  readFromFile:assetsCarPath];
                NSLog(@"资源编译后 %@大小：%lu 字节",[path lastPathComponent],[fileData length]);
                resourceSize += [fileData length];
                    
                removeFile(assetsCarPath);//remove file
            }else if ([lastPathComponent hasSuffix:@"git"] ||
                      [[lastPathComponent lowercaseString] hasSuffix:@"dsym"] ||
                      [[lastPathComponent lowercaseString] isEqualToString:@"demo"] ||
                      [[lastPathComponent lowercaseString] isEqualToString:@"document"]){
                //ignore git,demo,document
                return;
            }else{
                NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
                NSString * subPath = nil;
                //enumerate current directory's files
                for (NSString * str in dirArray) {
                    subPath  = [path stringByAppendingPathComponent:str];
                    BOOL issubDir = NO;
                    [fileManger fileExistsAtPath:subPath isDirectory:&issubDir];
                    enumAllFiles(subPath);
                }
            }
        }else{
            NSArray *array = [[lastPathComponent lowercaseString] componentsSeparatedByString:@"."];
            NSString *fileType = [array lastObject];
            //judge whether it is a resource
            if (isResource(fileType)) {
                //calculate resources' size
                NSData *fileData = [WBBladesFileManager  readFromFile:path];
                resourceSize += [fileData length];
            }else if([array count] == 1 || [fileType isEqualToString:@"a"]){//static library
                handleStaticLibrary(path);
            }else{//Probably it is a compiled intermediate files
            }
        }
    }
}

#pragma mark Tools
static BOOL isResource(NSString *type) {//resource type
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
        [type isEqualToString:@"rs"] ||
        [type isEqualToString:@"sty"] ||
        [type isEqualToString:@"cfg"] ||
        [type isEqualToString:@"strings"]) {
        return YES;
    }
    return NO;
}

static NSString *resultFilePath() {
    //result file path
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    return documentPath;
}
