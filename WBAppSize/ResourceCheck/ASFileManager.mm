//
//  ASFileManager.m
//  CarUnzip
//
//  Created by Shwnfee on 2022/1/17.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASFileManager.h"
#import "WBBladesFileManager.h"
#import "CarUnziper.h"
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/ldsyms.h>
#import <mach-o/getsect.h>
#import <objc/runtime.h>
#import "WBBladesDefines.h"
#import "WBBladesTool.h"
#import "ASNibDirectory.h"
#import "ASBundle.h"
#import "ASPlugIn.h"
#import "ASFramework.h"
#import "ASNibFile.h"
#import "ASImageFile.h"
#import "ASCarFile.h"
#import "ASMachOFile.h"
#import "NSString+ASUtils.h"
#import "ASUtils.h"

dispatch_queue_t _as_file_queue_t;

@interface ASFileManager ()

@property (nonatomic, strong) NSMutableDictionary * fileClassMap; // 文件数据模型注册表
@property (nonatomic, strong) NSMutableArray * allClassName; //所有文件数据模型
@property (nonatomic, strong) NSMutableDictionary * directoryClassMap; // 目录数据模型注册表

@end

@implementation ASFileManager

+ (instancetype)shareInstance{
    static dispatch_once_t onceToken;
    static ASFileManager * _manager;
    dispatch_once(&onceToken, ^{
        _manager = [[ASFileManager alloc] init];
    });
    return _manager;
}

#pragma mark - 资源模型管理

- (NSMutableDictionary *)fileClassMap{
    if (!_fileClassMap) {
        _fileClassMap = [NSMutableDictionary dictionary];
    }
    return _fileClassMap;
}

- (NSMutableArray *)allClassName{
    if (!_allClassName) {
        _allClassName =[NSMutableArray array];
    }
    return _allClassName;
}

- (NSMutableDictionary *)directoryClassMap{
    if (!_directoryClassMap) {
        _directoryClassMap = [NSMutableDictionary dictionary];
    }
    return _directoryClassMap;
}

- (void)registerFileModelClassString:(NSString *)classString withFileType:(NSString *)fileType{
    if ([fileType isKindOfClass:[NSString class]] && [fileType length]!=0) {
        [self.fileClassMap setObject:classString forKey:fileType];
    }
    if (![self.allClassName containsObject:classString]) {
        [self.allClassName addObject:classString];
    }
}

- (void)registerDirectoryModelClassString:(NSString *)classString withDirectoryType:(NSString *)directoryType{
    [self.directoryClassMap setObject:classString forKey:directoryType];
}

- (ASBaseFile *)createFileModelByFilePath:(NSString *)filePath{
    NSString * fileType = [ASUtils typeInPath:filePath];
    NSString * fileClassString = self.fileClassMap[fileType];
    Class fileModelClass;
    if ([fileClassString isKindOfClass:[NSString class]]) {
        fileModelClass = NSClassFromString(fileClassString);
    }else{
        for (NSString * checkName in self.allClassName) {
            Class checkClass = NSClassFromString(checkName);
            if (![checkClass respondsToSelector:@selector(checkFileTypeByPath:)]) {
                continue;
            }
            if ([checkClass checkFileTypeByPath:filePath]) {
                fileModelClass = checkClass;
                break;
            }
        }
    }
    if (![fileModelClass isSubclassOfClass:[ASBaseFile class]]) {
        fileModelClass = [ASBaseFile class];
    }
    ASBaseFile * baseFile = [fileModelClass fileWithPath:filePath];
    return baseFile;
}

- (ASBaseDirectory *)createDirectoryModelByDirectoryPath:(NSString *)directoryPath{
    NSString * directoryType = [ASUtils typeInPath:directoryPath];
    NSString * directoryClassString = self.directoryClassMap[directoryType];
    Class directoryClass;
    if ([directoryClassString isKindOfClass:[NSString class]]) {
        directoryClass = NSClassFromString(directoryClassString);
    }
    if (![directoryClass isSubclassOfClass:[ASBaseDirectory class]]) {
        directoryClass = [ASBaseDirectory class];
    }
    ASBaseDirectory * baseFile = [directoryClass directoryWithPath:directoryPath];
    return baseFile;
}

#pragma mark - 无用资源检查

+ (void)outPutUnusedPic:(NSArray *)result outPath:(NSString *)outPath{
    NSMutableDictionary * unusedResultDict = [NSMutableDictionary dictionary];
    for (ASImageFile * file in result) {
        NSString * bundleName = file.bundleName;
        if (!bundleName) {
            bundleName = @"Main.bundle";
        }
        NSMutableArray * unusedResult = unusedResultDict[bundleName];
        if (![unusedResult isKindOfClass:[NSMutableArray class]]) {
            unusedResult = [NSMutableArray array];
            unusedResultDict[bundleName] = unusedResult;
        }
        NSMutableDictionary * info = [NSMutableDictionary dictionary];
        info[@"name"]=file.fileName;
        info[@"path"]=file.filePath;
        info[@"size"]=@(file.inputSize);
        [unusedResult addObject:info];
    }
    [unusedResultDict writeToFile:[outPath stringByAppendingPathComponent:@"unusedPic1.plist"] atomically:YES];
}


+ (NSArray<ASBaseFile *> *)checkUnusedPictureOfBundle:(ASMainBundle *)mainBundle {
    NSMutableDictionary * stringInfos = [NSMutableDictionary dictionary];
    for (ASNibFile * nibFile in mainBundle.all.nibFiles) {
        NSString * nibPath = nibFile.filePath;
        NSDictionary * nibInfo = [ASUtils obtainNibInfoForNibPath:nibPath];
        if (nibInfo) {
            [stringInfos addEntriesFromDictionary:nibInfo];
        }
    }
    NSDictionary * cfstringDict =  [self cfStringOfMainBundle:mainBundle];
    [stringInfos addEntriesFromDictionary:cfstringDict];

    NSMutableArray * unUsedPic = [NSMutableArray array];
    //检测mainBundle内，未打进.car文件的图片资源的使用情况
    NSUInteger index = 0;
    for (ASImageFile * file in mainBundle.all.pngFiles) {
        @autoreleasepool {
            for (NSString * usingName  in [file mayUsingNames]) {
                if ([stringInfos objectForKey:usingName]) {
                    file.usingState = ASFileUsingYES;
                }
            }
        }
        if (file.usingState == ASFileUsingUnKnow) {
            file.usingState = ASFileUsingNO;
            [unUsedPic addObject:file];
        }
        index += 1;

    }
    index = 0;
    //检测.car内图片资源的使用情况
    for (ASCarFile * carFile in mainBundle.all.carFiles) {
        for (ASImageFile * imgFile in carFile.images) {
            @autoreleasepool {
                for (NSString * usingName  in [imgFile mayUsingNames]) {
                    if ([stringInfos objectForKey:usingName]) {
                        imgFile.usingState = ASFileUsingYES;
                    }
                }
                if (imgFile.usingState == ASFileUsingUnKnow||imgFile.usingState == ASFileUsingNO) {
                    imgFile.usingState = ASFileUsingNO;
                    [unUsedPic addObject:imgFile];
                }
            }
        }
        index += 1;
    }
    return unUsedPic;
}

+ (NSArray<ASBaseFile *>*)checkUnusedAssetsOfBundleByDefault:(ASMainBundle *)mainBundle
{
    NSArray *types = @[@"xib",@"plist",@"mp3",@"mp4",@"png",@"jpg",@"json",@"htm",@"html",@"p12",@"db",@"js",@"aiff",@"patch",@"dat",@"strings",@"ttf",@"gif"];
    return [ASFileManager checkUnusedAssetsOfBundle:mainBundle withFileTypes:types];
}

+ (NSArray<ASBaseFile *>*)checkUnusedAssetsOfBundle:(ASMainBundle *)mainBundle withFileTypes:(NSArray <NSString *>*)fileTypes{
    NSMutableDictionary * typesInfo = [NSMutableDictionary dictionary];
    for (NSString * fileType in fileTypes) {
        NSString * fileTypeString = [NSString stringWithFormat:@"%@",fileType];
        [typesInfo setObject:@"" forKey:fileTypeString];
    }
    
    NSMutableDictionary * stringInfos = [NSMutableDictionary dictionary];
    for (ASNibFile * nibFile in mainBundle.all.nibFiles) {
        NSString * nibPath = nibFile.filePath;
        NSDictionary * nibInfo = [ASUtils obtainNibInfoForNibPath:nibPath];
        if (nibInfo) {
            [stringInfos addEntriesFromDictionary:nibInfo];
        }
    }
    NSDictionary * cfstringDict =  [self cfStringOfMainBundle:mainBundle];
    [stringInfos addEntriesFromDictionary:cfstringDict];
    NSMutableArray * unUsedFiles = [NSMutableArray array];
    for (ASBaseFile * file in mainBundle.all.allFiles) {
        @autoreleasepool {
            if (![typesInfo objectForKey:file.fileType]) {
                continue;
            }
            
            if ([file isKindOfClass:[ASCarFile class]]) {
                for (ASBaseFile * carSubFile in [(ASCarFile *)file images]) {
                    carSubFile.isInCarFile = YES;
                    [unUsedFiles addObject:carSubFile];
                }
                continue;
            }
            
            
            for (NSString * usingName  in [file mayUsingNames]) {
                if ([stringInfos objectForKey:usingName]) {
                    file.usingState = ASFileUsingYES;
                }
            }
            if (file.usingState == ASFileUsingUnKnow||file.usingState == ASFileUsingNO) {
                file.usingState = ASFileUsingNO;
                [unUsedFiles addObject:file];
            }
        }
    }
    return unUsedFiles;
}

#pragma mark - 本地图片信息获取

+ (NSArray *)imageFileMoreThanSize:(NSUInteger)size fromPath:(NSString *)path{
    BOOL isDirectory = NO;
    NSFileManager * fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:path isDirectory:&isDirectory]) {
        return @[];
    }
    if (!isDirectory) {
        NSString * filePath = path;
        NSUInteger dataSize = [ASUtils bytesSizeForFile:filePath];
        ASImageFile * file = [[ASImageFile alloc] init];
        file.inputSize = dataSize;
        file.filePath = filePath;
        file.fileName = [filePath lastPathComponent];
        file.usingState = ASFileUsingUnKnow;
        return @[file];
    }
    
    NSMutableArray * result = [NSMutableArray array];
    
    NSArray * subPaths = [fileManager subpathsAtPath:path];
    for (NSString * subPath in subPaths) {
        NSString * filePath = [path stringByAppendingPathComponent:subPath];
        BOOL isDirectory;
        [fileManager fileExistsAtPath:filePath isDirectory:&isDirectory];
        if (!isDirectory && [ASImageFile isImageFile:filePath]) {
            NSUInteger dataSize = [ASUtils bytesSizeForFile:filePath];
            if (dataSize>size) {
                ASImageFile * file = [[ASImageFile alloc] init];
                file.inputSize = dataSize;
                file.filePath = filePath;
                file.fileName = [subPath lastPathComponent];
                file.usingState = ASFileUsingUnKnow;
                [result addObject:file];
            }
        }
    }
    [result sortUsingComparator:^NSComparisonResult(ASImageFile *   _Nonnull obj1, ASImageFile *  _Nonnull obj2) {
        if (obj1.inputSize>obj2.inputSize) {
            return NSOrderedAscending;
        }else if (obj1.inputSize<obj2.inputSize){
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];
    return result;
}


#pragma mark - 二进制文件字符串读取

+ (NSDictionary *)cfStringOfMainBundle:(ASMainBundle *)mainBundle{
    NSMutableDictionary * stringInfo = [NSMutableDictionary dictionary];
    for (ASMachOFile * macOFile in mainBundle.all.machOFiles) {
        NSData * arm64Binary = [WBBladesFileManager readArm64FromFile:macOFile.filePath];
        NSDictionary * cfStrings = [self cfStringOfBinary:arm64Binary];
        [stringInfo addEntriesFromDictionary:cfStrings];
    }
    return stringInfo;
}

+ (NSDictionary *)cfStringOfBinary:(NSData *)arm64Binary{
    NSUInteger offset = 0;
    struct mach_header_64 mhHeader;
    [arm64Binary getBytes:&mhHeader range:NSMakeRange(offset, sizeof(struct mach_header_64))];
    if (mhHeader.filetype != MH_EXECUTE && mhHeader.filetype != MH_DYLIB) {
        NSLog(@"参数异常，-unused 参数不是可执行文件");
        return @{};
    }
    struct section_64 cstringList= {0};
    cstringList.offset = -1;
    struct section_64 cfstringList= {0};
//    struct segment_command_64 linkEdit = {0};
    unsigned long long currentLcLocation = sizeof(struct mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        struct load_command *cmd = (struct load_command *)malloc(sizeof(struct load_command));
        [arm64Binary getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(struct load_command))];
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            struct segment_command_64 segmentCommand;
            [arm64Binary getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(struct segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];
            if ((segmentCommand.maxprot &( VM_PROT_WRITE | VM_PROT_READ)) == (VM_PROT_WRITE | VM_PROT_READ)) {
                //enumerate section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(struct segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    struct section_64 sectionHeader;
                    [arm64Binary getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(struct section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    //note CFstring
                    if ([secName isEqualToString:DATA_CSTRING]) {
                        cfstringList = sectionHeader;
                    }
                    //note Cstring
                    if ([secName isEqualToString:TEXT_CSTRING]) {
                        cstringList = sectionHeader;
                    }
                    currentSecLocation += sizeof(struct section_64);
                }
            }else if ([segName isEqualTo:SEGMENT_TEXT]){
                //enumerate section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(struct segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    struct section_64 sectionHeader;
                    [arm64Binary getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(struct section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    //note Cstring
                    if ([secName isEqualToString:TEXT_CSTRING]) {
                        cstringList = sectionHeader;
                    }
                    currentSecLocation += sizeof(struct section_64);
                }
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    NSMutableDictionary *cfStringDictionary = [NSMutableDictionary dictionary];
    NSMutableDictionary *cStringDictionary = [NSMutableDictionary dictionary];
    [self readCFStringList:cfstringList set:cfStringDictionary fileData:arm64Binary];
    [self readCStringList:cstringList set:cStringDictionary fileData:arm64Binary];
    [cfStringDictionary addEntriesFromDictionary:cStringDictionary];
    
    
    return cfStringDictionary;
}

+ (void)readCFStringList:(struct section_64)cfstringList set:(NSMutableDictionary *)cfStringSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(cfstringList.offset, 0);
    unsigned long long max = [fileData length];
    for (int i = 0; i < cfstringList.size / sizeof(struct cfstring64); i++) {
         @autoreleasepool {
             struct cfstring64 cfstring;
             NSData *data = [WBBladesTool readBytes:range length:sizeof(struct cfstring64) fromFile:fileData];
             [data getBytes:&cfstring range:NSMakeRange(0, sizeof(struct cfstring64))];
             unsigned long long stringOff = [WBBladesTool getOffsetFromVmAddress:cfstring.stringAddress fileData:fileData];
             if (stringOff > 0 && stringOff < max) {
                 uint8_t *buffer = (uint8_t *)malloc(cfstring.size + 1); buffer[cfstring.size] = '\0';
                 [fileData getBytes:buffer range:NSMakeRange(stringOff, cfstring.size)];
                 NSString *cfString = NSSTRING(buffer);
                 free(buffer);
                 if (cfString){
                     [cfStringSet setObject:@"1" forKey:cfString];
                 }
             }
         }
     }
}

+ (void)readCStringList:(struct section_64)cstringList set:(NSMutableDictionary *)cStringSet fileData:(NSData *)fileData {
    unsigned long long start_loc = cstringList.offset;
    unsigned long long max = cstringList.offset + cstringList.size;
    unsigned long long step = start_loc;
    while (step<max) {
        @autoreleasepool {
            NSRange range = NSMakeRange(step, 1);
            char *buffer = (char *)malloc(1);
            [fileData getBytes:buffer range:range];
            if (*buffer == 0) {
                unsigned long long str_len = step - start_loc;
                if (str_len>0) {
                    char *str_buffer = (char *)malloc(str_len+1); str_buffer[str_len] = '\0';
                    [fileData getBytes:str_buffer range:NSMakeRange(start_loc, str_len)];
                    NSString *cString = [NSString stringWithCString:str_buffer encoding:NSUTF8StringEncoding];
                    if (cString) {
                        [cStringSet setObject:@"1" forKey:cString];
                    }
                    free(str_buffer);
                }
                start_loc = step + 1;
            }
            free(buffer);
            step++;
        }
    }
}

#pragma mark - 文件资源信息数据读取

+ (void)load{
    _as_file_queue_t = dispatch_queue_create("ASFile_Operation", DISPATCH_QUEUE_SERIAL);
}

static ASMainBundle * _mainBundle = nil;
+ (ASMainBundle *)mainBundleWithAppPath:(NSString *)appPath{
    if (!appPath || appPath.length<0) {
        return nil;
    }
    if (_mainBundle&&[_mainBundle.appPath isEqualToString:appPath]) {
        return _mainBundle;
    }
    _mainBundle = [ASMainBundle directoryWithPath:appPath];
    return _mainBundle;
}

+ (void)duplicateFilesIn:(ASMainBundle *)mainBundle callBack:(void(^)(NSDictionary *))callBack{
    dispatch_async(_as_file_queue_t, ^{
        NSMutableDictionary * checkDictionary = [NSMutableDictionary dictionary];
        NSMutableDictionary * allDuplicateFilesDict = [NSMutableDictionary dictionary];
        for (ASBaseFile * file in mainBundle.all.allFiles) {
            @autoreleasepool {
                NSString * fileSHA256 = [NSString as_getFileSHA256StrFromPath:file.filePath];
                if (checkDictionary[fileSHA256]) {
                    NSMutableArray * duplicateFiles = allDuplicateFilesDict[fileSHA256];
                    if (!duplicateFiles) {
                        duplicateFiles = [NSMutableArray array];
                        [duplicateFiles addObject:checkDictionary[fileSHA256]];
                        [duplicateFiles addObject:file];
                        allDuplicateFilesDict[fileSHA256] = duplicateFiles;
                    }else{
                        [duplicateFiles addObject:file];
                    }
                }
                checkDictionary[fileSHA256] = file;
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (callBack) {
                callBack(allDuplicateFilesDict);
            }
        });
    });
}

+ (NSDictionary *)duplicateFilesIn:(ASMainBundle *)mainBundle {
    NSMutableDictionary * checkDictionary = [NSMutableDictionary dictionary];
    NSMutableDictionary * allDuplicateFilesDict = [NSMutableDictionary dictionary];
    for (ASBaseFile * file in mainBundle.all.allFiles) {
        @autoreleasepool {
            NSString * fileSHA256 = [NSString as_getFileSHA256StrFromPath:file.filePath];
            if (checkDictionary[fileSHA256]) {
                NSMutableArray * duplicateFiles = allDuplicateFilesDict[fileSHA256];
                if (!duplicateFiles) {
                    duplicateFiles = [NSMutableArray array];
                    [duplicateFiles addObject:checkDictionary[fileSHA256]];
                    [duplicateFiles addObject:file];
                    allDuplicateFilesDict[fileSHA256] = duplicateFiles;
                }else{
                    [duplicateFiles addObject:file];
                }
            }
            checkDictionary[fileSHA256] = file;
        }
    }
    return allDuplicateFilesDict;
}



#pragma mark - ToolMethods
+ (void)unzipCarAtMainBundle:(ASMainBundle *)mainBundle callBack:(void(^)(void))callBack{
    if ([NSThread isMainThread]) {
        [self _unzipCarAtMainBundle:mainBundle callBack:callBack];
    }else{
        dispatch_async(dispatch_get_main_queue(), ^{
            [self _unzipCarAtMainBundle:mainBundle callBack:callBack];
        });
    }
}

+ (void)_unzipCarAtMainBundle:(ASMainBundle *)mainBundle callBack:(void(^)(void))callBack{
    __block NSUInteger count=0;
    NSArray * carFiles = [mainBundle.all.carFiles copy];
    if (carFiles.count==0) {
        if (callBack) {
            callBack();
        }
        return;
    }
    [carFiles enumerateObjectsUsingBlock:^(ASCarFile * carFile, NSUInteger idx, BOOL * _Nonnull stop) {
        if (![carFile isKindOfClass:[ASCarFile class]]) {
            count++;
            return;
        }
        [carFile unzipCarFile:^{
            count++;
            if (count == carFiles.count) {
                [mainBundle recountSize];
                if (callBack) {
                    callBack();
                }
            }
        }];
    }];
}

@end
