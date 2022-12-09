//
//  WBBladesFileManager+StaticLibs.m
//  WBBlades
//
//  Created by wbblades on 2022/4/27.
//

#import "WBBladesFileManager+StaticLibs.h"
#import "WBBladesScanManager+StaticLibs.h"
#import "WBBladesCMD.h"

@implementation WBBladesFileManager (StaticLibs)

#pragma mark Scan Static Libs



+ (WBBladesStaticLibraryModel *)scanFrameworkWithOriginalPath:(NSString *)path  frameworkName:(NSString *)frameworkName{
    WBBladesStaticLibraryModel *frameworkModel = nil;
    NSFileManager * fileManger = [NSFileManager defaultManager];
    
    NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
    for (NSString * eachDir in dirArray) {
        NSString * subPath  = [path stringByAppendingPathComponent:eachDir];
        BOOL isDir = NO;
        [fileManger fileExistsAtPath:subPath isDirectory:&isDir];
        if (isDir) {
            frameworkModel = [self scanFrameworkWithOriginalPath:subPath frameworkName:frameworkName];
            if (frameworkModel) {
                break;
            }
        }else if (([frameworkName containsString:eachDir] || ([[[frameworkName componentsSeparatedByString:@"."] firstObject] caseInsensitiveCompare:eachDir] == NSOrderedSame)) && ![eachDir containsString:@"."]) {
            WBBladesStaticLibraryModel *model = [self scanStaticLibWithOriginalPath:subPath frameworkName:frameworkName];
            frameworkModel = model;
            break;
        }
    }
    return frameworkModel;
}

+ (WBBladesStaticLibraryModel *)scanStaticLibWithOriginalPath:(NSString *)path frameworkName:(NSString *)frameworkName{
    removeCopyFile(path);//remove file
    copyFile(path);//copy file
    thinFile(path);//arm64 file
    
    NSString *copyPath = [path stringByAppendingString:@"_copy"];
    NSData *fileData = [WBBladesFileManager  readFromFile:copyPath];
    
    removeCopyFile(path);//remove file
    
    WBBladesStaticLibraryModel *model = [WBBladesScanManager scanStaticLibraryModel:fileData];
    model.name = frameworkName;
    return model;
}

@end
