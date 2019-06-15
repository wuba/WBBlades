//
//  WBBladesScanManager.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#import "WBBladesObjectHeader.h"
#import "WBBladesSymTab.h"
#import "WBBladesStringTab.h"
#import "WBBladesObject.h"

#define NSSTRING(C_STR) [NSString stringWithCString: (char *)(C_STR) encoding: [NSString defaultCStringEncoding]]
#define CSTRING(NS_STR) [(NS_STR) cStringUsingEncoding: [NSString defaultCStringEncoding]]


@implementation WBBladesScanManager

+ (void)scanStaticLibrary:(NSData *)fileData{
    
    if (![self isSupport:fileData]) {
        return;
    }
    NSRange range = NSMakeRange(8, 0);
    WBBladesObjectHeader * symtabHeader = [self scanSymtabHeader:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(symtabHeader.range), 0);
    WBBladesSymTab * symTab = [self scanSymbolTab:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(symTab.range), 0);
    WBBladesStringTab * stringTab = [self scanStringTab:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(stringTab.range), 0);
    WBBladesObject *object = [self scanObject:fileData range:range];
    
}

+ (WBBladesObject *)scanObject:(NSData *)fileData range:(NSRange&)range{
    range = [self rangeAlign:range];
    
    //扫描头
    WBBladesObject *object = [WBBladesObject  new];
    object.objectHeader = [self scanObjectHeader:fileData range:range];
    
    //扫描Mach-O
    
    
    return object;
}

+ (WBBladesObjectHeader *)scanObjectHeader:(NSData *)fileData range:(NSRange&)range{
    
    NSRange tmpRange = range;
    NSUInteger len = fileData.length - tmpRange.location;
    //为了复用符号表的获取代码,截取二进制
    NSData *tmpData = [self read_bytes:tmpRange length:len fromFile:fileData];
    NSRange headerRange = NSMakeRange(0, 0);
    WBBladesObjectHeader * objcHeader = [self scanSymtabHeader:tmpData range:headerRange];
    objcHeader.range = NSMakeRange(range.location, objcHeader.range.length);
    return objcHeader;
}

//return ((mach_header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64);

+ (WBBladesObjectMachO *)scanObjectMachO:(NSData *)fileData range:(NSRange&)range{
    WBBladesObjectMachO *objcMachO = [WBBladesObjectMachO new];
    
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
    
    //获取load command
    
    
    
    return objcMachO;
}

//扫描符号表
+ (WBBladesSymTab *)scanSymbolTab:(NSData *)fileData range:(NSRange)range{
    range = [self rangeAlign:range];
    unsigned long long location = range.location;
    WBBladesSymTab *symTab = [WBBladesSymTab new];
    
    //获取符号表大小
    NSData *data = [self read_bytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];
    symTab.size = size;
    
    //获取符号表
    NSMutableArray *symbols = [NSMutableArray array];
    unsigned int symbolCount = (symTab.size - sizeof(unsigned int))/8;
    for (int i = 0; i < symbolCount; i++) {
        WBBladesSymbol *symbol = [WBBladesSymbol new];
        NSData * indexData = [self read_bytes:range length:4 fromFile:fileData];
        unsigned int index = 0;
        [indexData getBytes:&index range:NSMakeRange(0, 4)];
        
        unsigned int offset = 0;
        NSData *offsetData = [self read_bytes:range length:4 fromFile:fileData];
        [offsetData getBytes:&offset range:NSMakeRange(0, 4)];

        [symbols addObject:symbol];
    }
    symTab.symbols = [symbols copy];
    symTab.range = NSMakeRange(location, size + sizeof(unsigned int));//size 不包括自身的4字节，所以需要 + 4
    return symTab;
}

//扫描字符串表
+ (WBBladesStringTab *)scanStringTab:(NSData *)fileData range:(NSRange) range{
    
    //字符串表不存在字节对齐
//    range = [self rangeAlign:range];
    unsigned long long location = range.location;
    
    WBBladesStringTab *stringTab = [WBBladesStringTab new];
    //获取字符串表大小
    NSData *data = [self read_bytes:range length:4 fromFile:fileData];
    unsigned int size = 0;
    [data getBytes:&size range:NSMakeRange(0, 4)];
    
    //获取所有的字符串信息
    stringTab.strings = [self read_strings:range fixlen:size fromFile:fileData];
    
    //同理，字符串表长度也不包含自身4字节
    stringTab.range = NSMakeRange(location, size + sizeof(unsigned int));
    return stringTab;
}

//扫描符号表头
+ (WBBladesObjectHeader *)scanSymtabHeader:(NSData *)fileData range:(NSRange )range{
    
    range = [self rangeAlign:range];
    
    WBBladesObjectHeader *header = [[WBBladesObjectHeader alloc] init];
    
    header.name = [self read_string:range fixlen:16 fromFile:fileData];
    header.timeStamp = [self read_string:range fixlen:12 fromFile:fileData];
    header.userID = [self read_string:range fixlen:6 fromFile:fileData];
    header.groupID = [self read_string:range fixlen:6 fromFile:fileData];
    header.mode = [self read_string:range fixlen:8 fromFile:fileData];
    header.size = [self read_string:range fixlen:8 fromFile:fileData];
    NSMutableString * padding = [[NSMutableString alloc] initWithCapacity:2];

    for(;;){
        [padding appendString:[self read_string:range fixlen:1 fromFile:fileData]];
        if (*(CSTRING(padding) + [padding length] - 1) != ' '){
            [padding appendString:[self read_string:range fixlen:1 fromFile:fileData]];
            break;
        }
    }
    header.endHeader = padding;
    if (NSEqualRanges([header.name rangeOfString:@"#1/"], NSMakeRange(0,3))){
        uint32_t len = [[header.name substringFromIndex:3] intValue];
        header.longName = [self read_string:range fixlen:len fromFile:fileData];
    }
    header.range = range;
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
        case FAT_MAGIC:
        case FAT_CIGAM:
        {
            NSLog(@"fat binary");
        } break;
            
        case MH_MAGIC:
        case MH_CIGAM:
        {
            NSLog(@"32位 mach-o");
        } break;
            
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        {
            NSLog(@"64位 mach-o");
        } break;
        default:
        {
            if (*(uint64_t*)((uint8_t *)[fileData bytes]) == *(uint64_t*)"!<arch>\n"){
                NSLog(@"符合单架构静态库特征");
                return YES;
            }
        }
    }
    return NO;
}

+ (NSArray *)read_strings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData{
    range = NSMakeRange(NSMaxRange(range),len);
    NSMutableArray *strings = [NSMutableArray array];

    unsigned long size = 0;
    uint8_t * buffer = (uint8_t *)malloc(len + 1); buffer[len] = '\0';
    [fileData getBytes:buffer range:range];
    uint8_t *p = buffer;
    while (size < len) {
        NSString * str = NSSTRING(p);
        str = [self replaceEscapeCharsInString:str];
        if (str) {
            [strings addObject:str];
            NSLog(@"字符串%@",str);
            //+1 是为了留出'\0'的位置
            size = [str length] + size + 1;
            p = p + [str length] + 1;
        }
    }
    free (buffer);
    return [strings copy];
}

//-----------------------------------------------------------------------------
+ (NSString *)read_string:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData
{
    range = NSMakeRange(NSMaxRange(range),len);
    uint8_t * buffer = (uint8_t *)malloc(len + 1); buffer[len] = '\0';
    [fileData getBytes:buffer range:range];
    NSString * str = NSSTRING(buffer);
    free (buffer);
    return [self replaceEscapeCharsInString:str];
}

//-----------------------------------------------------------------------------
+ (NSData *)read_bytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData
{
    range = NSMakeRange(NSMaxRange(range),length);
    uint8_t * buffer = (uint8_t *)malloc(length);
    [fileData getBytes:buffer range:range];
    NSData * ret = [NSData dataWithBytes:buffer length:length];
    free (buffer);
    return ret;
}

//-----------------------------------------------------------------------------
+ (NSString *) replaceEscapeCharsInString: (NSString *)orig
{
    NSUInteger len = [orig length];
    NSMutableString * str = [[NSMutableString alloc] init];
    SEL sel = @selector(characterAtIndex:);
    unichar (*charAtIdx)(id, SEL, NSUInteger) = (typeof(charAtIdx)) [orig methodForSelector:sel];
    for (NSUInteger i = 0; i < len; i++)
    {
        unichar c = charAtIdx(orig, sel, i);
        switch (c)
        {
            default:    [str appendFormat:@"%C",c]; break;
            case L'\f': [str appendString:@"\\f"]; break; // form feed - new page (byte 0x0c)
            case L'\n': [str appendString:@"\\n"]; break; // line feed - new line (byte 0x0a)
            case L'\r': [str appendString:@"\\r"]; break; // carriage return (byte 0x0d)
            case L'\t': [str appendString:@"\\t"]; break; // horizontal tab (byte 0x09)
            case L'\v': [str appendString:@"\\v"]; break; // vertical tab (byte 0x0b)
        }
    }
    return str;
}

@end
