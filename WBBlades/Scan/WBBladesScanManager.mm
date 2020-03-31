//
//  WBBladesScanManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
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
//scan static library size
+ (unsigned long long)scanStaticLibrary:(NSData *)fileData {
    
    //judge whether it is a static library
    if ([fileData length] < sizeof(mach_header) || ![self isSupport:fileData]) {
        return 0;
    }
    NSMutableArray *objects = [NSMutableArray array];
    
    //Get the file eigenvalue
    mach_header header = *(mach_header*)((mach_header *)[fileData bytes]);
    
    if (header.filetype == MH_OBJECT) {//it is a object file
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

+ (WBBladesObjectMachO *)scanObjectMachO:(NSData *)fileData range:(NSRange)range {
    
    //use eight-byte alignment
    range = [self rangeAlign:range];
    
    //note __TEXT's size, __DATA's size
    WBBladesObjectMachO *objcMachO = [WBBladesObjectMachO new];
    objcMachO.sections = [NSMutableDictionary dictionary];
    
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
                    objcMachO.size += sectionHeader.size;
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
        }
        
        currentLcLocation += cmd->cmdsize;
        
        free(cmd);
    }
    
    objcMachO.range = NSMakeRange(mhHeaderLocation, stringTabEnd - mhHeaderLocation);
    
    return objcMachO;
}

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
//use eight-bytes alignment
+ (NSRange)rangeAlign:(NSRange)range {
    unsigned long long location = NSMaxRange(range);
    location = 8 * ceil(location / 8.0);
    return NSMakeRange(location, range.length);
}

//judge whether the file is supported
+ (BOOL)isSupport:(NSData *)fileData {
    
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    switch (magic) {
        case FAT_MAGIC: //fat binary file
        case FAT_CIGAM:
        {
            NSLog(@"fat binary");
        } break;
            
        case MH_MAGIC: //32 bit mach-o
        case MH_CIGAM:
        {
            NSLog(@"32位 mach-o");
        } break;
            
        case MH_MAGIC_64://64 bit mach-o
        case MH_CIGAM_64:
        {
            //a single object
            NSLog(@"64位 mach-o");
            return YES;
        } break;
        default:
        {
            //it is a static library
            if (*(uint64_t*)((uint8_t *)[fileData bytes]) == *(uint64_t*)"!<arch>\n") {
                //                NSLog(@"符合单架构静态库特征");
                return YES;
            } else {
                NSLog(@"非Mach-O文件");
            }
        }
    }
    return NO;
}

@end

