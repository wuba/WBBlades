//
//  ASMachOFile.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ASMachOFile.h"
#import "ASFileManager.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import "WBBladesFileManager.h"
#import "ASUtils.h"
@implementation ASMachOFile

+ (void)load{
    [[ASFileManager shareInstance] registerFileModelClassString:NSStringFromClass([ASMachOFile class]) withFileType:@"dylib"];
}

+ (BOOL)checkFileTypeByPath:(NSString *)filePath{
    return [self isMachOFile:filePath];
}

+ (BOOL)isMachOFile:(NSString *)filePath{
    NSString * fileName = [filePath lastPathComponent];
    NSArray * nameParts = [fileName componentsSeparatedByString:@"."];
    if (nameParts.count>1) {
        NSString * type = [nameParts lastObject];
        if (![type isEqualToString:@"dylib"]) {
            return NO;
        }
    }    
    CGFloat size = [ASUtils bytesSizeForFile:filePath];
    if (size<4) {
        return NO;
    }
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath: filePath];
    [inputStream open];
    uint8_t readBuffer[4];
    //是否已经到结尾标识
    [inputStream read:readBuffer maxLength:4];
    unsigned int head_magic_num = *((unsigned int *)readBuffer);
    if (head_magic_num == MH_MAGIC
        || head_magic_num == MH_CIGAM
        || head_magic_num == MH_MAGIC_64
        || head_magic_num == MH_CIGAM_64
        || head_magic_num == FAT_MAGIC
        || head_magic_num == FAT_CIGAM
        || head_magic_num == FAT_MAGIC_64
        || head_magic_num == FAT_CIGAM_64
        ) {
        return YES;
    }
    return NO;
}

+ (instancetype)fileWithPath:(NSString *)filePath{
    ASMachOFile * machOFile = [super fileWithPath:filePath];
    
    NSData * arm64Binary = [WBBladesFileManager readArm64FromFile:filePath];
    NSData * fileData = arm64Binary;
    NSUInteger offset = 0;
    struct mach_header_64 mhHeader;
    [arm64Binary getBytes:&mhHeader range:NSMakeRange(offset, sizeof(struct mach_header_64))];
    if (mhHeader.filetype != MH_EXECUTE && mhHeader.filetype != MH_DYLIB) {
        NSLog(@"参数异常，-unused 参数不是可执行文件");
        return machOFile;
    }
    unsigned long long currentLcLocation = sizeof(struct mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        struct load_command* cmd = (struct load_command *)malloc(sizeof(struct load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(struct load_command))];
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            struct segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(struct segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];
            machOFile.mainSegmentInfo[segName] = @(segmentCommand.filesize);
           
        }else if(cmd->cmd == LC_SYMTAB){
            struct symtab_command symTabCommand;
            [fileData getBytes:&symTabCommand range:NSMakeRange(currentLcLocation, sizeof(struct symtab_command))];
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    return machOFile;
}

- (NSMutableDictionary *)mainSegmentInfo{
    if (!_mainSegmentInfo) {
        _mainSegmentInfo = [NSMutableDictionary dictionary];
    }
    return _mainSegmentInfo;
}

- (NSString *)mainSegmentSizeDiscription{
    NSString * result = @"";
    for (NSString * key in self.mainSegmentInfo.allKeys) {
        NSNumber * size = self.mainSegmentInfo[key];
        result = [result stringByAppendingFormat:@"%@:%@ ",key,[ASUtils discriptionWithByteSize:size.unsignedLongLongValue]];
    }
    return result;
}

@end
