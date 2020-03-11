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
static void scanUnusedClass(int argc, const char * argv[]);
static void scanCrashSymbol(int argc, const char * argv[]);
static NSString *resultFilePath(void);

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSInteger type = [[NSString stringWithFormat:@"%s",argv[1]] integerValue];
        if (type == WBBladesTypeStaticLibSize) {
            //1 + static lib path
            scanStaticLibrary(argc, argv);//scan static library size
            
        }else if (type == WBBladesTypeUnusedClass){
            //2 + APP executable file + static lib path1 + static lib path2 ...
            scanUnusedClass(argc, argv);//scan unused class
            
        }else if(type == WBBladesTypeCrashLog){
            //3 + APP executable file + crash offset1,crash offset2...
            scanCrashSymbol(argc, argv);//crash log symbolicate
        }
    }
}

#pragma mark Scan Function
static void scanStaticLibrary(int argc, const char * argv[]) {
    
    //param1:type  params2:libs' path list
    for (int i = 0; i < argc - 2; i++) {
        @autoreleasepool {
            NSString *podPath = [NSString stringWithFormat:@"%s",argv[i+2]];//each pods' path
            NSLog(@"Pod 路径：%@", podPath);
            
            NSString *podName = [podPath lastPathComponent];//pod's name
            
            NSString *outPutPath = resultFilePath();//result output path
            outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesResult.plist"];
            
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:outPutPath];//last result
            NSMutableDictionary *resultData = [[NSMutableDictionary alloc] initWithDictionary:plist];
            podResult = [NSMutableDictionary dictionary];
            
            resourceSize = 0;//empty the resources' size
            codeSize = 0;//empty the codes' size
            
            enumAllFiles(podPath);//enumerate all pods' files
            
            //color prints each pod's resources' size and code's sizes
            colorPrint([NSString stringWithFormat:@"codeSize = %llu KB\n resourceSize = %llu KB", codeSize/1024,resourceSize/1024]);
            
            //write results to file
            [podResult setValue:[NSString stringWithFormat:@"%.2f MB",resourceSize/1024.0/1024] forKey:@"resource"];
            [podResult setValue:[NSString stringWithFormat:@"%.2f MB", (codeSize + resourceSize) / 1024.0 / 1024] forKey:@"total"];
            [resultData setValue:podResult forKey:podName];
            [resultData writeToFile:outPutPath atomically:YES];
        }
    }
}

static void scanUnusedClass(int argc, const char * argv[]) {
    s_classSet = [NSMutableSet set];
    NSString *podName = @"";
    
    if (argc < 3) {//at least three params
        NSLog(@"参数不足");
        return;
    }

    //enumerate all pods and all classes
    for (int i = 3; i < argc; i++) {
        @autoreleasepool {
            NSString *podPath = [NSString stringWithFormat:@"%s",argv[i]];
            NSLog(@"读取%@所有类", podPath);
            enumPodFiles(podPath);
            NSString *tmp = [podPath lastPathComponent];
            tmp = [@" " stringByAppendingString:tmp];
            podName = [podName stringByAppendingString:tmp];
        }
    }
    NSString *appPath = [NSString stringWithFormat:@"%s",argv[2]];
    
    //read binary files, scan all pods and classes to find unused classes
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
    [resultData setObject:classes forKey:podName];
    [resultData writeToFile:outPutPath atomically:YES];
}

static void scanCrashSymbol(int argc, const char * argv[]) {
    NSString *appPath = [NSString stringWithFormat:@"%s", argv[2]];
    NSString *crashAddress = [NSString stringWithFormat:@"%s", argv[3]];
    
    NSDictionary *result = [WBBladesScanManager symbolizeWithMachOFile:[WBBladesFileManager readArm64FromFile:appPath] crashOffsets:crashAddress];
    
    //write results to file
    NSString *outPutPath = resultFilePath();
    outPutPath = [outPutPath stringByAppendingPathComponent:@"WBBladesCrash.plist"];
    [result writeToFile:outPutPath atomically:YES];
}

#pragma mark Handle
void handleStaticLibrary(NSString *filePath) {
    
    NSString *name = [filePath lastPathComponent];//static library's name
    NSLog(@"分析文件---%@", name);
    
    removeCopyFile(filePath);//remove file
    copyFile(filePath);//copy file
    
    thinFile(filePath);//arm64 file
    
    //read mach-o file and calculate size
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
    unsigned long long size = [WBBladesScanManager scanStaticLibrary:fileData];
    NSLog(@"%@ 大小为 %.2f MB", name, (size) / 1024.0 / 1024.0);
    codeSize += size;
    
    removeCopyFile(filePath);//remove tmp file
    colorPrint([NSString stringWithFormat:@"%@ 链接后大小 %llu 字节", name, size]);
    if (size > 0) {
        [podResult setValue:[NSString stringWithFormat:@"%.2f MB",size / 1024.0 / 1024] forKey:name];
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
static void enumPodFiles(NSString *path) {
    
    //enumerate each pod
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
        //enumerate each pod
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
