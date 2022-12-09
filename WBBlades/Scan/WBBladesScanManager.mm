//
//  WBBladesScanManager.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/14.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesScanManager.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>

#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"
#import "WBBladesLinkManager.h"
#import "WBBladesDefines.h"
#import "WBBladesFileManager.h"
#import "WBBladesTool.h"
#import "WBBladesDefines.h"

@implementation WBBladesScanManager

/**
 功能：扫描和提取静态库文件中的数据。首先会判断当前文件类型。可能存在单一目标文件的静态库、动态库、多目标文件静态库等几种可能。其中动态库直接获取文件大小。静态库则需要根据目标文件进行提取数据计算
 fileData：传入的文件二进制
 */
//scan static library size
+ (unsigned long long)scanStaticLibrary:(NSData *)fileData {
    
    //异常判断，架构检测
    if ([fileData length] < sizeof(mach_header_64) || ![WBBladesTool isSupport:fileData]) {
        return 0;
    }
    NSMutableArray *objects = [NSMutableArray array];
    
    //获取文件的header
    mach_header_64 header = *(mach_header_64*)((mach_header_64 *)[fileData bytes]);
    
    if (header.filetype == MH_OBJECT) {
        WBBladesObject *object = [WBBladesObject new];
        NSRange range = NSMakeRange(0, 0);

        //create mach-O file
        WBBladesObjectMachO *macho = [self scanObjectMachO:fileData range:range];
        object.objectMachO = macho;
        [objects addObject:object];
    } else if (header.filetype == MH_DYLIB || header.filetype == MH_EXECUTE) {//it is a dynamic library or  executable file
        return [fileData length];
    } else {
        //symbol table header
        NSRange range = NSMakeRange(8, 0);
        WBBladesObjectHeader *symtabHeader = [self scanSymtabHeader:fileData range:range];

        //symbol table
        range = NSMakeRange(NSMaxRange(symtabHeader.range), 0);
        WBBladesSymTab *symTab = [self scanSymbolTab:fileData range:range];

        //string table
        range = NSMakeRange(NSMaxRange(symTab.range), 0);
        WBBladesStringTab *stringTab = [self scanStringTab:fileData range:range];

        range = NSMakeRange(NSMaxRange(stringTab.range), 0);

        //scan all of the object files
        while (range.location < fileData.length) {
            @autoreleasepool {
                WBBladesObject *object = [self scanObject:fileData range:range];
                range = NSMakeRange(NSMaxRange(object.range), 0);
                [objects addObject:object];
                range = [self rangeAlign:range];
            }
        }
    }

    //virtual linking all of the object files
    unsigned long long linkSize = [[WBBladesLinkManager shareInstance] linkWithObjects:objects];
    return linkSize;
}

/**
 功能：从二进制文件的指定位置读取相应的数据。并且这段数据会被当做目标文件来读取和解析。先读Header，再读目标文件。
 fileData：从磁盘中读取的二进制文件。
 range：目标文件的位置
 */
//scan object file and return model
+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange)range {
    range = [self rangeAlign:range];

    //scan header
    WBBladesObject *object = [WBBladesObject  new];
    object.objectHeader = [self scanObjectHeader:fileData range:range];

    range = NSMakeRange(NSMaxRange(object.objectHeader.range), 0);

    //scan mach=o file
    WBBladesObjectMachO *machO = [self scanObjectMachO:fileData range:range];
    object.objectMachO = machO;
    object.range = NSMakeRange(object.objectHeader.range.location, NSMaxRange(machO.range) - object.objectHeader.range.location);
    return object;
}

/**
 功能：从指定位置读取目标文件对应的Header
 fileData：从磁盘中读取的二进制文件
 range：目标文件的位置
 */
+ (WBBladesObjectHeader *)scanObjectHeader:(NSData *)fileData range:(NSRange)range {

    NSRange tmpRange = range;
    NSUInteger len = fileData.length - tmpRange.location;
    //reuse symbol table code,intercepting binary
    NSData *tmpData = [WBBladesTool readBytes:tmpRange length:len fromFile:fileData];
    NSRange headerRange = NSMakeRange(0, 0);
    WBBladesObjectHeader *objcHeader = [self scanSymtabHeader:tmpData range:headerRange];
    objcHeader.range = NSMakeRange(range.location, objcHeader.range.length);
    return objcHeader;
}

/**
 功能：从指定位置读取目标文件对应的Header
 fileData：从磁盘中读取的二进制文件
 range：目标文件的位置
 */
+ (WBBladesObjectMachO *)scanObjectMachO:(NSData *)fileData range:(NSRange)range {

    //use eight-byte alignment
    range = [self rangeAlign:range];

    //note __TEXT's size, __DATA's size
    WBBladesObjectMachO *objcMachO = [WBBladesObjectMachO new];
    objcMachO.sections = [NSMutableDictionary dictionary];
    objcMachO.undefinedSymbols = [NSMutableSet set];
    objcMachO.definedSymbols = [NSMutableSet set];

    //64 bit mach-o file's magic number == 0XFEEDFACF
    unsigned int magicNum = 0;
    NSRange tmpRange = NSMakeRange(range.location, 4);
    [fileData getBytes:&magicNum range:tmpRange];
    if (magicNum != MH_MAGIC_64 && magicNum != MH_CIGAM_64) {
        NSLog(@"暂时不处理非64位文件");
        exit(0);
    }

    //mach-o header
    mach_header_64 mhHeader;
    tmpRange = NSMakeRange(range.location, sizeof(mach_header_64));
    [fileData getBytes:&mhHeader range:tmpRange];
    unsigned long long mhHeaderLocation = range.location;
    unsigned long long stringTabEnd = mhHeaderLocation;

    //load command
    unsigned long long lcLocation = range.location + sizeof(mach_header_64);
    unsigned long long currentLcLocation = lcLocation;

    //enumerate load command
    for (int i = 0; i < mhHeader.ncmds; i++) {

        //load command data
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        //if load command is a segment type,extract data and text
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)

            //command data
            segment_command_64 segmentCommand;//struct
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];

            unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);

            //enumerate section header
            for (int j = 0; j < segmentCommand.nsects; j++) {

                //each section header's data
                section_64 sectionHeader;
                [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                NSString *segName = [[NSString alloc] initWithUTF8String:sectionHeader.segname];

                //__TEXT size + __DATA size + __DATA_CONST size + __RODATA size
                if ([segName isEqualToString:SEGMENT_TEXT] ||
                    [segName isEqualToString:SEGMENT_RODATA] ||
                    [segName isEqualToString:SEGMENT_DATA] ||
                    [segName isEqualToString:SEGMENT_DATA_CONST]) {
                    NSString * sectname = [NSString stringWithFormat:@"%s",sectionHeader.sectname];
                     //TEXT_EH_FRAME 异常调试相关，链接时不计入
                     if (![sectname isEqual: TEXT_EH_FRAME]) {
                         objcMachO.size += sectionHeader.size;
                    }
                }

                //save for virtual linking
                if ([segName isEqualToString:SEGMENT_TEXT] || [segName isEqualToString:SEGMENT_RODATA]) {

                    //jump to corresponding section
                    unsigned int secOffset = sectionHeader.offset;
                    unsigned long long secLocation = mhHeaderLocation + secOffset;
                    NSString *sectionName = [NSString stringWithFormat:@"(%@,%s)",segName,sectionHeader.sectname];
                    NSRange secRange = NSMakeRange(secLocation, 0);

                    //get the section content based on the section data type
                    switch (sectionHeader.flags & SECTION_TYPE) {
                        case S_CSTRING_LITERALS: {

                            NSArray *array = [WBBladesTool readStrings:secRange fixlen:sectionHeader.size fromFile:fileData];
                            [objcMachO.sections setObject:array forKey:sectionName];
                        }
                            break;
                        case S_4BYTE_LITERALS: {
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 4; k++) {
                                NSData *literals = [WBBladesTool readBytes:secRange length:4 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];

                        }
                            break;
                        case S_8BYTE_LITERALS: {
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 8; k++) {
                                NSData *literals = [WBBladesTool readBytes:secRange length:8 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];
                        }
                            break;
                        case S_16BYTE_LITERALS: {
                            NSMutableArray *array = [NSMutableArray array];
                            for (int k = 0; k < sectionHeader.size / 16; k++) {
                                NSData *literals = [WBBladesTool readBytes:secRange length:16 fromFile:fileData];
                                if (literals) {
                                    [array addObject:literals];
                                }
                            }
                            [objcMachO.sections setObject:[array copy] forKey:sectionName];
                        }
                            break;

                        case S_REGULAR: {
                            if ([sectionName isEqualToString:CHINESE_STRING_SECTION]) {
                                //chinese string
                                NSData *data = [WBBladesTool readBytes:secRange length:sectionHeader.size fromFile:fileData];

                                unsigned short *head = (unsigned short *)[data bytes];
                                unsigned short *start = head;
                                unsigned short *end = head;
                                NSMutableArray *array = [NSMutableArray array];

                                while (start <= head + (data.length) / sizeof(short)) {
                                    if (* end == 0x0000) {
                                        unsigned long size = (end - start) * sizeof(short) + sizeof(short);
                                        NSData *tmp = [NSData dataWithBytes:start length:size];
                                        NSString *uString = [[NSString alloc] initWithData:tmp encoding:NSUTF16LittleEndianStringEncoding];
                                        start = end + 1;
                                        if (uString.length > 0) {
                                            [array addObject:uString];
                                        }
                                    }
                                    end ++;
                                }
                                [objcMachO.sections setObject:[array copy] forKey:sectionName];

                            } else if ([sectionName isEqualToString:TEXT_SWIFT5_REFLSTR]||
                                       [sectionName isEqualToString:TEXT_SWIFT5_TYPEREF]) {

                                    NSArray *array = [WBBladesTool readStrings:secRange fixlen:sectionHeader.size fromFile:fileData];
                                    [objcMachO.sections setObject:array forKey:sectionName];
                            }
                        }
                        default:
                            break;
                    }
                }

                currentSecLocation += sizeof(section_64);
            }
        } else if (cmd->cmd == LC_SYMTAB) {//fining string table

            //get end of mach-o file based on end of string
            symtab_command symtabCommand;
            [fileData getBytes:&symtabCommand range:NSMakeRange(currentLcLocation, sizeof(symtab_command))];
            stringTabEnd = mhHeaderLocation + symtabCommand.stroff + symtabCommand.strsize;
            
            NSData *data = [fileData subdataWithRange:NSMakeRange(mhHeaderLocation + symtabCommand.stroff, symtabCommand.strsize)];

            for (int i=0; i <symtabCommand.nsyms; i++) {
                nlist_64 nlist;
                NSRange nlistRange = NSMakeRange(i * sizeof(nlist_64) + symtabCommand.symoff + range.location, sizeof(nlist_64));
                [fileData getBytes:&nlist range:nlistRange];
                
                ptrdiff_t off = nlist.n_un.n_strx;
                char * p = (char *)data.bytes;
                p = p+off;
                
                NSString *symbol = [NSString stringWithFormat:@"%s",p];
                symbol = [symbol stringByReplacingOccurrencesOfString:@"\u0001" withString:@" "];
                if ((nlist.n_type & 0xe)== 0x0) {//N_UNDF
                    [objcMachO.undefinedSymbols addObject:symbol];
                }else if ((nlist.n_type & 0xe)== 0x2){//N_ABS
                    [objcMachO.definedSymbols addObject:symbol];
                }else if ((nlist.n_type & 0xe)== 0xe && (nlist.n_type & 0x1)== 0x1){//N_SECT && N_EXT
                    [objcMachO.definedSymbols addObject:symbol];
                }else if ((nlist.n_type & 0xe)== 0xc){//N_PBUD
                    [objcMachO.definedSymbols addObject:symbol];
                }else if ((nlist.n_type & 0xe)== 0xa){//N_INDR
                    [objcMachO.definedSymbols addObject:symbol];
                }
            }
        }

        currentLcLocation += cmd->cmdsize;

        free(cmd);
    }

    objcMachO.range = NSMakeRange(mhHeaderLocation, stringTabEnd - mhHeaderLocation);

    return objcMachO;
}

/**
    功能：获取静态库中的符号表，目前获取到相应数据后没有做任何使用。
    fileData：从磁盘中读取的二进制文件
    range：符号表的位置
 */
//scan symbol table and return model
+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range {
    range = [self rangeAlign:range];
    unsigned long long location = range.location;
    WBBladesSymTab *symTab = [WBBladesSymTab new];

    //symbol table size
    NSData *data = [WBBladesTool readBytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];
    symTab.size = size;

    //symbol table
    NSMutableArray *symbols = [NSMutableArray array];
    unsigned int symbolCount = (symTab.size - sizeof(unsigned int)) / 8;
    for (int i = 0; i < symbolCount; i++) {
        WBBladesSymbol *symbol = [WBBladesSymbol new];
        NSData *indexData = [WBBladesTool readBytes:range length:4 fromFile:fileData];
        unsigned int index = 0;
        [indexData getBytes:&index range:NSMakeRange(0, 4)];

        unsigned int offset = 0;
        NSData *offsetData = [WBBladesTool readBytes:range length:4 fromFile:fileData];
        [offsetData getBytes:&offset range:NSMakeRange(0, 4)];

        symbol.symbolIndex = index;
        symbol.offset = offset;

        [symbols addObject:symbol];
    }
    symTab.symbols = [symbols copy];
    symTab.range = NSMakeRange(location, size + sizeof(unsigned int));//this size does not include the size of the self,plus 4 bytes
    return symTab;
}

/**
    功能：获取静态库中的字符串表，目前获取到相应数据后没有做任何使用。
    fileData：从磁盘中读取的二进制文件
    range：字符串的位置
 */
//scan string table and return model
+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range {

    //string table can be regardless of byte alignment
    unsigned long long location = range.location;

    WBBladesStringTab *stringTab = [WBBladesStringTab new];

    //string table size
    NSData *data = [WBBladesTool readBytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];

    stringTab.strings = [WBBladesTool readStrings:range fixlen:size fromFile:fileData];

    //this size does not include the size of the self,plus 4 bytes
    stringTab.range = NSMakeRange(location, size + sizeof(unsigned int));
    return stringTab;
}

/**
    功能：获取静态库中的Symtab Header，目前获取到相应数据后没有做任何使用。
    fileData：从磁盘中读取的二进制文件
    range：Symtab Header的位置
 */
//scan symbol table header and return model
+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range{

    range = [self rangeAlign:range];
    unsigned long long location = range.location;

    WBBladesObjectHeader *header = [[WBBladesObjectHeader alloc] init];

    header.name = [WBBladesTool readString:range fixlen:16 fromFile:fileData];
    header.timeStamp = [WBBladesTool readString:range fixlen:12 fromFile:fileData];
    header.userID = [WBBladesTool readString:range fixlen:6 fromFile:fileData];
    header.groupID = [WBBladesTool readString:range fixlen:6 fromFile:fileData];
    header.mode = [WBBladesTool readString:range fixlen:8 fromFile:fileData];
    header.size = [WBBladesTool readString:range fixlen:8 fromFile:fileData];
    NSMutableString *padding = [[NSMutableString alloc] initWithCapacity:2];

    for (;;) {
        [padding appendString:[WBBladesTool readString:range fixlen:1 fromFile:fileData]];
        if (*(CSTRING(padding) + [padding length] - 1) != ' ') {
            [padding appendString:[WBBladesTool readString:range fixlen:1 fromFile:fileData]];
            break;
        }
    }
    header.endHeader = padding;
    if (NSEqualRanges([header.name rangeOfString:@"#1/"], NSMakeRange(0,3))) {
        uint32_t len = [[header.name substringFromIndex:3] intValue];
        header.longName = [WBBladesTool readString:range fixlen:len fromFile:fileData];
    }
    header.range = NSMakeRange(location, NSMaxRange(range) - location);
    return header;
}

#pragma mark Tools
/**
    功能：每段数据读取时需要做8字节对齐，否则会出现异常。
    range：需要做8字节对齐的数据，只修正location
 */
//use eight-bytes alignment
+ (NSRange)rangeAlign:(NSRange)range {
    unsigned long long location = NSMaxRange(range);
    location = 8 * ceil(location / 8.0);
    return NSMakeRange(location, range.length);
}

@end


