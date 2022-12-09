//
//  WBBladesHelper.m
//  WBBlades
//
//  Created by 竹林七闲 on 2022/4/11.
//

#import "WBBladesInterface.h"

//
//  main.m
//  WBBlades
//
//  Created by 竹林七闲 on 2022/4/8.
//

#import <Foundation/Foundation.h>
#import <WBBlades/WBBladesCMD.h>
#import <WBBlades/WBBladesScanManager.h>
#import <WBBlades/WBBladesFileManager.h>
#import <WBBlades/WBBladesLinkManager.h>
#import <WBBlades/WBBladesScanManager+UnuseClassScan.h>
#import <WBBlades/WBBladesScanManager+AutoHook.h>
#import <WBBlades/WBBladesScanManager+CrashSymbol.h>
#import <WBBlades/WBBladesFileManager+StaticLibs.h>

static BOOL isResource(NSString *type);
static void enumAllFiles(NSString *path);
static void enumLibFiles(NSString *path);

static unsigned long long resourceSize = 0;
static unsigned long long codeSize = 0;

static NSDictionary *sizeResult;
static NSMutableSet *s_classSet;

#pragma mark Handle
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
                NSString *currentResourceInfo = [NSString stringWithFormat:@"资源编译后 %@大小：%lu 字节",[path lastPathComponent],[fileData length]];
                NSLog(@"%@", currentResourceInfo);
                [WBBladesInterface shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [WBBladesInterface shareInstance].libarySizeInfos, currentResourceInfo];
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
//                handleStaticLibrary(path);
                [WBBladesInterface handleStaticLibrary:path];
            }else{//Probably it is a compiled intermediate files
            }
        }
    }
}

#pragma mark Tools
static BOOL isResource(NSString *type) {//resource type
    if ([type isEqualToString:@"nib"] ||
        [type isEqualToString:@"zip"] ||
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

 NSString *resultFilePath() {
    //result file path
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    return documentPath;
}



@implementation WBBladesInterface

+ (WBBladesInterface *)shareInstance {
    static dispatch_once_t onceToken;
    static WBBladesInterface *interface;
    dispatch_once(&onceToken, ^{
        interface = [[WBBladesInterface alloc]init];
    });
    return interface;
}

+ (void)handleStaticLibrary:(NSString *)filePath {
    NSString *name = [filePath lastPathComponent];//static library's name
    NSLog(@"分析文件---%@", name);
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@%@", [self shareInstance].libarySizeInfos, @"分析文件---", name];
    removeCopyFile(filePath);//remove file
    copyFile(filePath);//copy file
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos, @"正在提取arm64架构"];
    thinFile(filePath);//arm64 file
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos, @"正在去除bitcode中间码..."];
    stripBitCode(filePath);//strip file

    NSArray *array = [[filePath lowercaseString] componentsSeparatedByString:@"."];
    NSString *fileType = [array lastObject];
    if ([fileType isEqualToString:@"a"]) { //动态库不剥离符号表，静态库剥离， 因为通常AppStore包会剥离。但AppStore包不会自动剥离动态库的符号表，所有这里忽略动态库
        [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos, @"正在剥离符号表..."];
        stripDysmSymbol(filePath);
    }
    //read mach-o file and calculate size
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager readFromFile:copyPath];
    unsigned long long size = [WBBladesScanManager scanStaticLibrary:fileData];
    NSString *sizeContent = [NSString stringWithFormat:@"%@ 大小为 %.2f MB", name, (size) / 1024.0 / 1024.0];
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos, sizeContent];
    NSLog(@"%@ 大小为 %.2f MB", name, (size) / 1024.0 / 1024.0);
    codeSize += size;

    removeCopyFile(filePath);//remove tmp file
    colorPrint([NSString stringWithFormat:@"%@ 链接后大小 %llu 字节", name, size]);
    if (size > 0) {
        [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB",size / 1024.0 / 1024] forKey:name];
    }
}

+ (void)autoHookByInputPaths:(NSString *)filePath {
    [self shareInstance].autoHookInfos = @"";
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [WBBladesScanManager getAllOCClasses:filePath];
    });
}
+ (void)endAutoHookProcess {
    [WBBladesScanManager endAutoHookProcess];
}

+ (void)scanStaticLibraryByInputPath:(NSString *)libPath {
    [self shareInstance].libarySizeInfos = @"";
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
    NSString *totalResourceInfo = [NSString stringWithFormat:@"codeSize = %llu KB\nresourceSize = %llu KB", codeSize/1024,resourceSize/1024];
    colorPrint(totalResourceInfo);
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos,  totalResourceInfo];
//    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].libarySizeInfos, @"分析文件---", name];
    //write results to file
    [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB",resourceSize/1024.0/1024] forKey:@"resource"];
    [sizeResult setValue:[NSString stringWithFormat:@"%.2f MB", (codeSize + resourceSize) / 1024.0 / 1024] forKey:@"total"];
    [resultData setValue:sizeResult forKey:libName];
    [resultData writeToFile:outPutPath atomically:YES];
}

+ (void)scanUnusedClassByInputPaths: (NSArray<NSString *>*)inputPath {
    NSString *appFilePath = [[NSUserDefaults standardUserDefaults] stringForKey:@"unused"];
    [self scanUnusedClassWithAppPath:appFilePath fromLibs:inputPath];
}

+ (NSArray<NSDictionary<NSString *, NSNumber *> *> *)scanUnusedClassWithAppPath:(NSString *)appFilePath fromLibs:(NSArray<NSString *> *)fromLibsPath {
    s_classSet = [NSMutableSet set];
    NSString *outputPath = [[NSUserDefaults standardUserDefaults] stringForKey:@"o"];
    [self shareInstance].unusedClassInfos = [NSString stringWithFormat:@"开始分析文件---%@", [appFilePath lastPathComponent]];
    if (fromLibsPath.count > 0) {
        //enumerate all libs and all classes
        [fromLibsPath enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            NSLog(@"读取%@所有类", obj);
            [self shareInstance].unusedClassInfos = [NSString stringWithFormat:@"%@\n开始提取指定库：%@中的所有类...", [self shareInstance].unusedClassInfos, [obj lastPathComponent]];
            enumLibFiles(obj);
        }];
    }

    NSString *appPath = getAppPathIfIpa(appFilePath);

    //read binary files, scan all libs and classes to find unused classes
    [self shareInstance].unusedClassInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].unusedClassInfos, @"正在提取arm64架构"];
    NSData *appData = [WBBladesFileManager readArm64FromFile:appPath];
    
    [self shareInstance].unusedClassInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].unusedClassInfos, @"开始读取可执行文件..."];
    NSArray *classset = [WBBladesScanManager scanAllClassWithFileData:appData classes:s_classSet progressBlock:^(NSString *progressInfo) {
        [self shareInstance].unusedClassInfos = [NSString stringWithFormat:@"%@\n%@", [self shareInstance].unusedClassInfos, progressInfo];
    }];

    //write results to file
    if (outputPath.length == 0) {
        outputPath = resultFilePath();
        outputPath = [outputPath stringByAppendingPathComponent:@"UnusedClass.plist"];
        [classset writeToFile:outputPath atomically:YES];
    }else{
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:classset options:0 error:nil];
        NSString *strJson = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        [strJson writeToFile:outputPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }

    rmAppIfIpa(appFilePath);
    
    return classset;
}

+ (NSString *)scanCrashSymbolByCrashLogPath:(NSString *)crashLogPath executableAppPath:(NSString *)appPath{
    if (!crashLogPath || crashLogPath.length == 0 || !appPath || appPath.length == 0) {
        return @"";
    }
    
    if (![crashLogPath hasSuffix:@".app"]){
        return @"";
    }
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
    return outputLog;
}

//检测静态库之间依赖关系
+ (NSString *)scanDependLibs:(NSString *)folderPath{
    [self shareInstance].libarySizeInfos = @"";
    NSArray *staticLibs = [self scanAllStaticLibs:folderPath frameworkName:nil];
    
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n正在分析依赖关系", [self shareInstance].libarySizeInfos];
    NSMutableDictionary *resultDic = [NSMutableDictionary dictionary];
    for (WBBladesStaticLibraryModel *eachLibModel in staticLibs) {
        NSMutableDictionary *dependLibs = [NSMutableDictionary dictionary];
        for (WBBladesStaticLibraryModel *otherLibModel in staticLibs) {
            if (eachLibModel != otherLibModel) {//different libs
                NSMutableArray *dependSymbols = [NSMutableArray array];
                for (NSString *symbol in eachLibModel.undefinedSymbols) {
                    if ([otherLibModel.definedSymbols containsObject:symbol]) {
                        [dependSymbols addObject:symbol];
//                        NSLog(@"%@ depends on %@ : %@",eachLibModel.name,otherLibModel.name,symbol);
                    }
                }
                if (dependSymbols && dependSymbols.count > 0) {
                    [dependLibs setObject:dependSymbols forKey:otherLibModel.name];
                    [resultDic setObject:dependLibs forKey:eachLibModel.name];
                }
            }
        }
    }
    
    [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n分析已结束", [self shareInstance].libarySizeInfos];
    //output plist file
    if (resultDic && resultDic.allKeys && resultDic.allKeys.count>0) {
        NSString *outPutPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];//result output path
        
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy_MM_dd_HH_mm_ss"];
        [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Beijing"]];
        NSDate *date = [NSDate date];
        NSString *currentTimeString = [dateFormatter stringFromDate:date];
        
        outPutPath = [outPutPath stringByAppendingPathComponent:[NSString stringWithFormat:@"WBBladesLibDepend_%@.plist",currentTimeString]];
        [resultDic writeToFile:outPutPath atomically:YES];
        return outPutPath;
    }
    return @"";
}

+ (NSArray<WBBladesStaticLibraryModel *> *)scanAllStaticLibs:(NSString *)path frameworkName:(NSString*)frameworkName{
    NSMutableArray *staticLibs = [NSMutableArray array];
    
    NSFileManager * fileManger = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
    NSString *symbolicLink = [fileManger destinationOfSymbolicLinkAtPath:path error:NULL];
                   
    if (!isExist || symbolicLink) {//not exist or a symbolic link
        return nil;
    }
                   
    NSString *lastPathComponent = [path lastPathComponent];
    if (isDir && !frameworkName) {
        if ([lastPathComponent hasSuffix:@"xcassets"] ||
            [lastPathComponent hasSuffix:@"git"] ||
            [lastPathComponent hasSuffix:@"nib"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"demo"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"product"] ||
            [[lastPathComponent lowercaseString] isEqualToString:@"document"]) {
            //ignore resources,git,demo,product,document
            return nil;
        }else{
            NSLog(@"scanning folder %@",path);
            NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
            NSString * subPath = nil;
            for (NSString * eachDir in dirArray) {
                subPath  = [path stringByAppendingPathComponent:eachDir];
                NSString *frameworkName = ([eachDir hasSuffix:@".framework"]?eachDir:nil);
                NSArray *eachLibs = [self scanAllStaticLibs:subPath frameworkName:frameworkName];
                if (eachLibs && eachLibs.count>0) {
                    [staticLibs addObjectsFromArray:eachLibs];
                }
            }
        }
    }else if([lastPathComponent hasSuffix:@".a"]){
        [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n正在获取%@的符号信息", [self shareInstance].libarySizeInfos, lastPathComponent];
        WBBladesStaticLibraryModel *model = [WBBladesFileManager scanStaticLibWithOriginalPath:path frameworkName:lastPathComponent];
        [staticLibs addObject:model];
    }else if (frameworkName && frameworkName.length>0){
        [self shareInstance].libarySizeInfos = [NSString stringWithFormat:@"%@\n正在获取%@的符号信息", [self shareInstance].libarySizeInfos,  frameworkName];
        WBBladesStaticLibraryModel *model = [WBBladesFileManager scanFrameworkWithOriginalPath:path frameworkName:frameworkName];
        if (model != nil){
            [staticLibs addObject:model];
        }
       
    }
    return [staticLibs copy];
}
@end
