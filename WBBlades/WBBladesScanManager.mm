//
//  WBBladesScanManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager.h"
#import <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"
#import "WBBladesLinkManager.h"
#import <mach-o/nlist.h>
#import "WBBladesDefines.h"
#import "capstone.h"
#import <objc/runtime.h>
#import "WBBladesFileManager.h"
#import "WBBladesTool.h"

@implementation WBBladesScanManager

+ (unsigned long long)scanStaticLibrary:(NSData *)fileData{
    
    //判断是否为静态库文件
    if ([fileData length] < sizeof(mach_header) || ![self isSupport:fileData]) {
        return 0;
    }
    NSMutableArray *objects = [NSMutableArray array];
    
    //获取文件特征值
    mach_header header = *(mach_header*)((mach_header *)[fileData bytes]);
    //如果fileData 为目标文件，目标文件中只加入此目标文件
    if (header.filetype == MH_OBJECT) {
        WBBladesObject *object = [WBBladesObject new];
        NSRange range = NSMakeRange(0, 0);
        //提取Mach-O文件
        WBBladesObjectMachO *macho = [self scanObjectMachO:fileData range:range];
        object.objectMachO = macho;
        [objects addObject:object];
    }else if(header.filetype == MH_DYLIB){
        //动态库直接返回文件大小
        return [fileData length];
    }else{
        
        //header
        NSRange range = NSMakeRange(8, 0);
        WBBladesObjectHeader * symtabHeader = [self scanSymtabHeader:fileData range:range];
        
        //符号表
        range = NSMakeRange(NSMaxRange(symtabHeader.range), 0);
        WBBladesSymTab * symTab = [self scanSymbolTab:fileData range:range];
        
        //字符串表
        range = NSMakeRange(NSMaxRange(symTab.range), 0);
        WBBladesStringTab * stringTab = [self scanStringTab:fileData range:range];
        
        range = NSMakeRange(NSMaxRange(stringTab.range), 0);
        
        //循环扫描静态库中所有的目标文件
        while (range.location < fileData.length) {
            @autoreleasepool {
                WBBladesObject *object = [self scanObject:fileData range:range];
                range = NSMakeRange(NSMaxRange(object.range), 0);
                [objects addObject:object];
                range = [self rangeAlign:range];
            }
        }
    }
    
    //对所有的目标文件进行虚拟链接
    unsigned long long linkSize = [[WBBladesLinkManager shareInstance] linkWithObjects:objects];
    return linkSize;
}

+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange)range{
    range = [self rangeAlign:range];
    
    //扫描头
    WBBladesObject *object = [WBBladesObject  new];
    object.objectHeader = [self scanObjectHeader:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(object.objectHeader.range), 0);
    //扫描Mach-O
    WBBladesObjectMachO *machO = [self scanObjectMachO:fileData range:range];
    object.objectMachO = machO;
    object.range = NSMakeRange(object.objectHeader.range.location, NSMaxRange(machO.range) - object.objectHeader.range.location);
    return object;
}

+ (WBBladesObjectHeader *)scanObjectHeader:(NSData *)fileData range:(NSRange)range{
    
    NSRange tmpRange = range;
    NSUInteger len = fileData.length - tmpRange.location;
    //为了复用符号表的获取代码,截取二进制
    NSData *tmpData = [WBBladesTool read_bytes:tmpRange length:len fromFile:fileData];
    NSRange headerRange = NSMakeRange(0, 0);
    WBBladesObjectHeader * objcHeader = [self scanSymtabHeader:tmpData range:headerRange];
    objcHeader.range = NSMakeRange(range.location, objcHeader.range.length);
    return objcHeader;
}

+ (WBBladesObjectMachO *)scanObjectMachO:(NSData *)fileData range:(NSRange)range{
    
    //字节对齐
    range = [self rangeAlign:range];
    
    //记录__TEXT 和 __DATA的大小
    WBBladesObjectMachO *objcMachO = [WBBladesObjectMachO new];
    objcMachO.sections = [NSMutableDictionary dictionary];
    //64位 mach-o 文件的magic number == 0XFEEDFACF
    unsigned int magicNum = 0;
    NSRange tmpRange = NSMakeRange(range.location, 4);
    [fileData getBytes:&magicNum range:tmpRange];
    if (magicNum != MH_MAGIC_64 && magicNum != MH_CIGAM_64) {
        NSLog(@"暂时不处理非64位文件");
        exit(0);
    }
    
    //获取mach-o header
    mach_header_64 mhHeader;
    tmpRange = NSMakeRange(range.location, sizeof(mach_header_64));
    [fileData getBytes:&mhHeader range:tmpRange];
    unsigned long long mhHeaderLocation = range.location;
    unsigned long long stringTabEnd = mhHeaderLocation;
    
    //获取load command
    unsigned long long lcLocation = range.location + sizeof(mach_header_64);
    unsigned long long currentLcLocation = lcLocation;
    
    //遍历load command
    for (int i = 0; i < mhHeader.ncmds; i++) {
        
        //获取load command数据
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        //如果load command为 segment类型则进行文本段和数据段的提取
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            
            //重新以segment_command_64结构体类型来获取command数据
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            
            unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
            
            //遍历所有的section header
            for (int j = 0; j < segmentCommand.nsects; j++) {
                
                //获取segment_command后的每个secton信息
                section_64 sectionHeader;
                [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                NSString *segName = [[NSString alloc] initWithUTF8String:sectionHeader.segname];
                
                //获取section 信息，__TEXT 和 __DATA的大小统计到应用中
                if ([segName isEqualToString:@"__TEXT"] ||
                    [segName isEqualToString:@"__RODATA"] ||
                    [segName isEqualToString:@"__DATA"] ||
                    [segName isEqualToString:@"__DATA_CONST"]) {
                    objcMachO.size += sectionHeader.size;
                }
                
                //__TEXT的section 做存储，用于虚拟链接
                if ([segName isEqualToString:@"__TEXT"] || [segName isEqualToString:@"__RODATA"]) {
                    
                    //跳转到相应的section
                    unsigned int secOffset = sectionHeader.offset;
                    unsigned long long  secLocation = mhHeaderLocation + secOffset;
                    NSString *sectionName = [NSString stringWithFormat:@"(%@,%s)",segName,sectionHeader.sectname];
                    NSRange secRange = NSMakeRange(secLocation, 0);
                    
                    //根据section数据类型获取section 内容
                    switch (sectionHeader.flags & SECTION_TYPE) {
                        case S_CSTRING_LITERALS:{
                            
                            NSArray *array = [WBBladesTool read_strings:secRange fixlen:sectionHeader.size fromFile:fileData];
                            [objcMachO.sections setObject:array forKey:sectionName];
                        }
                            break;
                        case S_4BYTE_LITERALS:{
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 4; k++) {
                                NSData *literals = [WBBladesTool read_bytes:secRange length:4 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];
                            
                        }
                            break;
                        case S_8BYTE_LITERALS:{
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 8; k++) {
                                NSData *literals = [WBBladesTool read_bytes:secRange length:8 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];
                        }
                            break;
                        case S_16BYTE_LITERALS:{
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 16; k++) {
                                NSData *literals = [WBBladesTool read_bytes:secRange length:16 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];
                        }
                            break;
                        
                        case S_REGULAR:{
                            if ([sectionName isEqualToString:@"(__TEXT,__ustring)"]) {
                                //获取中文字符串
                                NSData *data = [WBBladesTool read_bytes:secRange length:sectionHeader.size fromFile:fileData];
                                
                                unsigned short *head = (unsigned short *)[data bytes];
                                unsigned short *start = head;
                                unsigned short *end = head;
                                NSMutableArray *array = [NSMutableArray array];
                                
                                while (start <= head + (data.length)/sizeof(short)) {
                                    if (* end == 0x0000) {
                                        unsigned long size = (end - start)*sizeof(short)+sizeof(short);
                                        NSData *tmp = [NSData dataWithBytes:start length:size];
                                        NSString *uString = [[NSString alloc] initWithData:tmp encoding:NSUTF16LittleEndianStringEncoding];
                                        start = end + 1;
                                        if (uString.length>0) {
                                            [array addObject:uString];
                                        }
                                    }
                                    end ++;
                                }
                                [objcMachO.sections setObject:[array copy] forKey:sectionName];
                            }
                        }
                        default:
                            break;
                    }
                }
                
                currentSecLocation += sizeof(section_64);
            }
        }else if (cmd->cmd == LC_SYMTAB){//查找字符串表
            
            //根据字符串的尾部 确定当前mach-o的尾部
            symtab_command symtabCommand;
            [fileData getBytes:&symtabCommand range:NSMakeRange(currentLcLocation, sizeof(symtab_command))];
            stringTabEnd = mhHeaderLocation + symtabCommand.stroff + symtabCommand.strsize;
        }
        
        currentLcLocation += cmd->cmdsize;
        
        free(cmd);
    }
    
    objcMachO.range = NSMakeRange(mhHeaderLocation, stringTabEnd - mhHeaderLocation);
    
    return objcMachO;
}

//扫描符号表
+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range{
    range = [self rangeAlign:range];
    unsigned long long location = range.location;
    WBBladesSymTab *symTab = [WBBladesSymTab new];
    
    //获取符号表大小
    NSData *data = [WBBladesTool read_bytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];
    symTab.size = size;
    
    //获取符号表
    NSMutableArray *symbols = [NSMutableArray array];
    unsigned int symbolCount = (symTab.size - sizeof(unsigned int))/8;
    for (int i = 0; i < symbolCount; i++) {
        WBBladesSymbol *symbol = [WBBladesSymbol new];
        NSData * indexData = [WBBladesTool read_bytes:range length:4 fromFile:fileData];
        unsigned int index = 0;
        [indexData getBytes:&index range:NSMakeRange(0, 4)];
        
        unsigned int offset = 0;
        NSData *offsetData = [WBBladesTool read_bytes:range length:4 fromFile:fileData];
        [offsetData getBytes:&offset range:NSMakeRange(0, 4)];
        
        symbol.symbolIndex = index;
        symbol.offset = offset;
        
        [symbols addObject:symbol];
    }
    symTab.symbols = [symbols copy];
    symTab.range = NSMakeRange(location, size + sizeof(unsigned int));//size 不包括自身的4字节，所以需要 + 4
    return symTab;
}

//扫描字符串表
+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range{
    
    //字符串表不存在字节对齐
    unsigned long long location = range.location;
    
    WBBladesStringTab *stringTab = [WBBladesStringTab new];
    //获取字符串表大小
    NSData *data = [WBBladesTool read_bytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];
    
    //获取所有的字符串信息
    stringTab.strings = [WBBladesTool read_strings:range fixlen:size fromFile:fileData];
    
    //同理，字符串表长度也不包含自身4字节
    stringTab.range = NSMakeRange(location, size + sizeof(unsigned int));
    return stringTab;
}

//扫描符号表头
+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range{
    
    range = [self rangeAlign:range];
    unsigned long long location = range.location;
    
    WBBladesObjectHeader *header = [[WBBladesObjectHeader alloc] init];
    
    header.name = [WBBladesTool read_string:range fixlen:16 fromFile:fileData];
    header.timeStamp = [WBBladesTool read_string:range fixlen:12 fromFile:fileData];
    header.userID = [WBBladesTool read_string:range fixlen:6 fromFile:fileData];
    header.groupID = [WBBladesTool read_string:range fixlen:6 fromFile:fileData];
    header.mode = [WBBladesTool read_string:range fixlen:8 fromFile:fileData];
    header.size = [WBBladesTool read_string:range fixlen:8 fromFile:fileData];
    NSMutableString * padding = [[NSMutableString alloc] initWithCapacity:2];
    
    for(;;){
        [padding appendString:[WBBladesTool read_string:range fixlen:1 fromFile:fileData]];
        if (*(CSTRING(padding) + [padding length] - 1) != ' '){
            [padding appendString:[WBBladesTool read_string:range fixlen:1 fromFile:fileData]];
            break;
        }
    }
    header.endHeader = padding;
    if (NSEqualRanges([header.name rangeOfString:@"#1/"], NSMakeRange(0,3))){
        uint32_t len = [[header.name substringFromIndex:3] intValue];
        header.longName = [WBBladesTool read_string:range fixlen:len fromFile:fileData];
    }
    header.range = NSMakeRange(location, NSMaxRange(range) - location);
    return header;
}

//字节对齐
+ (NSRange)rangeAlign:(NSRange)range{
    unsigned long long location = NSMaxRange(range);
    location = 8 * ceil(location / 8.0);
    return NSMakeRange(location, range.length);
}

+ (BOOL)isSupport:(NSData *)fileData{
    
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    switch (magic)
    {
        case FAT_MAGIC: //胖二进制文件
        case FAT_CIGAM:
        {
            NSLog(@"fat binary");
        } break;
            
        case MH_MAGIC: //32位mach-o
        case MH_CIGAM:
        {
            NSLog(@"32位 mach-o");
        } break;
            
        case MH_MAGIC_64://64位mach-o
        case MH_CIGAM_64:
        {
            //存在一个静态库为单目标文件的情况
            NSLog(@"64位 mach-o");
            return YES;
        } break;
        default:
        {
            //静态库文件的特征
            if (*(uint64_t*)((uint8_t *)[fileData bytes]) == *(uint64_t*)"!<arch>\n"){
                //                NSLog(@"符合单架构静态库特征");
                return YES;
            }else{
                NSLog(@"非Mach-O文件");
            }
        }
    }
    return NO;
}


@end

