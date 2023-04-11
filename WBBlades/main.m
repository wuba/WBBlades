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
#import <WBBlades/WBBladesScanManager+CrashSymbol.h>
#import <WBBlades/WBBladesInterface.h>
@import WBAppSize;

//scanStaticLibraryByInputPath

//static BOOL isResource(NSString *type);
//static void enumAllFiles(NSString *path);
//static void enumLibFiles(NSString *path);
//
//static unsigned long long resourceSize = 0;
//static unsigned long long codeSize = 0;

static NSDictionary *sizeResult;
static NSMutableSet *s_classSet;
static void scanStaticLibrary(int argc, const char * argv[]);
static void scanUnusedClass(int argc, const char * argv[]);
static void scanCrashSymbol(int argc, const char * argv[]);
static void scanCrashLog(int argc, const char * argv[]);
static void diagnose(int argc, const char * argv[]);

int main(int argc, const char *argv[]) {
    @autoreleasepool {

        NSString *staticLibSizeStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"size"];
        NSString *unusedClassStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"unused"];
        NSString *crashLogStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"symbol"];
        NSString *crashStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"crash"];
        NSString *thinStr = [[NSUserDefaults standardUserDefaults] stringForKey:@"diagnose"];

        if (staticLibSizeStr.length > 0) {
            scanStaticLibrary(argc, argv);//scan static library size
        }else if (unusedClassStr.length > 0){
            scanUnusedClass(argc, argv);//scan unused class
        }else if (crashLogStr.length > 0){
            scanCrashSymbol(argc, argv);//crash log symbolicate
        }else if (crashStr.length > 0){
            scanCrashLog(argc, argv);//crash log symbolicate
        }else if (thinStr.length > 0){
            diagnose(argc, argv);
        } else{
            NSLog(@"筛选检测无用代码：blades -unused xxx.app -from xxx.a xxx.a .... -o outputPath (-from 标识只分析以下静态库中的无用代码，不加此参数默认为APP中全部)");
            NSLog(@"分析多个静态库的体积：blades -size xxx.a xxx.framework ....");
            NSLog(@"日志符号化：blades -symbol xxx.app -logPath xxx.ips");
            NSLog(@"一键诊断：blades -diagnose xxx.app");
        }
    }
}

#pragma mark Scan Function
static void scanStaticLibrary(int argc, const char * argv[]) {

    //param1:type  params2:libs' path list
    for (int i = 0; i < argc - 2; i++) {
        @autoreleasepool {
            NSString *libPath = [NSString stringWithFormat:@"%s",argv[i+2]];//each libs' path
            [WBBladesInterface scanStaticLibraryByInputPath: libPath];
        }
    }
}

static void scanUnusedClass(int argc, const char * argv[]) {


    NSString *selectLibs = [[NSUserDefaults standardUserDefaults] stringForKey:@"from"];
    NSMutableArray <NSString *>*libPaths = [@[] mutableCopy];

    if (selectLibs.length > 0) {
        //enumerate all libs and all classes
        for (int i = 4; i < argc; i++) {
            @autoreleasepool {
                NSString *libPath = [NSString stringWithFormat:@"%s",argv[i]];
                [libPaths addObject:libPath];
            }
        }
    }
    [WBBladesInterface scanUnusedClassByInputPaths: libPaths];
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

static void scanCrashLog(int argc, const char * argv[]){
    if (argc < 3){
        return;
    }
}

/// 一键诊断
static void diagnose(int argc, const char * argv[]) {
    DiagnoseDataManager *manager = [[DiagnoseDataManager alloc] init];
    NSString *path = [NSString stringWithUTF8String:argv[2]];
    NSLog(@"%@", path);
    [manager diagnoseAppInCLIWithApp:path andProgressBlock:^(NSString * hint) {

    } andFinishBlock:^{

    }];
}
