//
//  WBBladesTool.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesTool.h"
#import "WBBladesDefines.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <dlfcn.h>
#import <string.h>

@implementation WBBladesTool

/**
 * @param range Indicate the start location of the buffer.
 * @param len The actural size of the buffer.
 * @param fileData The file data to be read.
 * @return The array contains the strings read from the file data.
 */
+ (NSArray *)readStrings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData {
    range = NSMakeRange(NSMaxRange(range), len);
    NSMutableArray *strings = [NSMutableArray array];
    
    unsigned long size = 0;
    uint8_t *buffer = (uint8_t *)malloc(len + 1); buffer[len] = '\0';
    [fileData getBytes:buffer range:range];
    uint8_t *p = buffer;
    
    while (size < len) {
        NSString *str = NSSTRING(p);
        str = [self replaceEscapeCharsInString:str];
        if (str) {
            [strings addObject:str];
            // +1 to leave a space for '\0'
            size = [str length] + size + 1;
            p = p + [str length] + 1;
        }
    }
    free (buffer);
    return [strings copy];
}

+ (NSString *)readString:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData {
    range = NSMakeRange(NSMaxRange(range), len);
    uint8_t *buffer = (uint8_t *)malloc(len + 1); buffer[len] = '\0';
    [fileData getBytes:buffer range:range];
    NSString *str = NSSTRING(buffer);
    free (buffer);
    return [self replaceEscapeCharsInString:str];
}

+ (NSString *)readString:(NSRange &)range fromFile:(NSData*)fileData{
    range.location = NSMaxRange(range);
    NSString * str = NSSTRING((uint8_t *)[fileData bytes] + range.location);
    range.length = [str length] + 1;
    return [self replaceEscapeCharsInString:str];
}

+ (int64_t)readSLEB128:(NSRange &)range fromFile:(NSData *)fileData{
    range.location = NSMaxRange(range);
    uint8_t * p = (uint8_t *)[fileData bytes] + range.location, *start = p;
    
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    
    do {
        byte = *p++;
        result |= ((byte & 0x7f) << bit);
        bit += 7;
    } while (byte & 0x80);
    
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 )
    {
        result |= (-1LL) << bit;
    }
    
    range.length = (p - start);
    return result;
}

+ (uint64_t)readULEB128:(NSRange &)range fromFile:(NSData *)fileData{
    range.location = NSMaxRange(range);
    uint8_t * p = (uint8_t *)[fileData bytes] + range.location, *start = p;
    
    uint64_t result = 0;
    int bit = 0;
    
    do {
        uint64_t slice = *p & 0x7f;
        
        if (bit >= 64 || slice << bit >> bit != slice)
            [NSException raise:@"uleb128 error" format:@"uleb128 too big"];
        else {
            result |= (slice << bit);
            bit += 7;
        }
    }
    while (*p++ & 0x80);
    
    range.length = (p - start);
    return result;
}

+ (NSData *)readBytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData {
    range = NSMakeRange(NSMaxRange(range), length);
    uint8_t *buffer = (uint8_t *)malloc(length);
    [fileData getBytes:buffer range:range];
    NSData *ret = [NSData dataWithBytes:buffer length:length];
    free (buffer);
    return ret;
}

+ (NSString *)replaceEscapeCharsInString:(NSString *)orig {
    NSUInteger len = [orig length];
    NSMutableString *str = [[NSMutableString alloc] init];
    SEL sel = @selector(characterAtIndex:);
    unichar (*charAtIdx)(id, SEL, NSUInteger) = (typeof(charAtIdx)) [orig methodForSelector:sel];
    for (NSUInteger i = 0; i < len; i++)
    {
        unichar c = charAtIdx(orig, sel, i);
        switch (c) {
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

+ (cs_insn *)disassemWithMachOFile:(NSData *)fileData  from:(unsigned long long)begin length:(unsigned long long )size {
    
    // Get compilation.
    char *ot_sect = (char *)[fileData bytes] + begin;
    uint64_t ot_addr = begin;
    csh cs_handle = 0;
    cs_insn *cs_insn = NULL;
    cs_err cserr;
    if ((cserr = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cs_handle)) != CS_ERR_OK ) {
        NSLog(@"Failed to initialize Capstone: %d, %s.", cserr, cs_strerror(cs_errno(cs_handle)));
        return NULL;
    }
    // Set the parsing mode.
    cs_option(cs_handle, CS_OPT_MODE, CS_MODE_ARM);
    //        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    // Disassemble
    size_t disasm_count = cs_disasm(cs_handle, (const uint8_t *)ot_sect, size, ot_addr, 0, &cs_insn);
    if (disasm_count < 1 ) {
        NSLog(@"汇编指令解析不符合预期！");
        return NULL;
    }
    return cs_insn;
}

+ (unsigned long long )getSegmentWithIndex:(int)index fromFile:(NSData *)fileData{
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    if (index >= mhHeader.ncmds || index < 0) {
        return 0;
    }
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            if (index == i) {
                
                free(cmd);
                return segmentCommand.vmaddr;
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    return 0;
}

+ (NSDictionary *)dynamicBindingInfoFromFile:(NSData *)fileData{
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    dyld_info_command dyldInfoCmd;
    
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_DYLD_INFO ||
            cmd->cmd == LC_DYLD_INFO_ONLY) {
            dyld_info_command segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(dyld_info_command))];
            dyldInfoCmd = segmentCommand;
            
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    NSMutableDictionary *allBindInfoDic = [NSMutableDictionary dictionary];
    NSDictionary *bindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.bind_off size:dyldInfoCmd.bind_size isLazyBind:NO fromFile:fileData];
    NSDictionary *weakBindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.weak_bind_off size:dyldInfoCmd.weak_bind_size isLazyBind:NO fromFile:fileData];
    NSDictionary *lazyBindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.lazy_bind_off size:dyldInfoCmd.lazy_bind_size isLazyBind:YES fromFile:fileData];
    [allBindInfoDic addEntriesFromDictionary:bindInfoDic];
    [allBindInfoDic addEntriesFromDictionary:weakBindInfoDic];
    [allBindInfoDic addEntriesFromDictionary:lazyBindInfoDic];
    return allBindInfoDic.copy;
}


+ (NSDictionary *)dynamicBindingInfoWithOffset:(unsigned long long)offset size:(unsigned long long)size isLazyBind:(BOOL)isLazyBind fromFile:(NSData *)fileData{
    
    NSMutableDictionary *bindInfoDic = [NSMutableDictionary dictionary];
    //code from macoview
    uint8_t byte;
    BOOL end = NO;
    unsigned long long address = 0;
    NSString *symbolName = @"";
    unsigned long long dylibIndex = 0;
    NSRange range = NSMakeRange(offset, 0);
    while (!end && range.location < offset + size) {
        @autoreleasepool {
            range.location = NSMaxRange(range);
            range.length = 1;
            [fileData getBytes:&byte range:range];
            
            uint8_t opcode = byte & BIND_OPCODE_MASK;
            uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
            
            switch (opcode) {
                case BIND_OPCODE_DONE:{
                    end = isLazyBind?NO:YES;
                    break;
                }
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:{
                    symbolName = [self readString:range fromFile:fileData];
                    break;
                }
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:{
                    uint32_t segmentIndex = immediate;
                    unsigned long long val = [self readULEB128:range fromFile:fileData];
                    address =  [self getSegmentWithIndex:segmentIndex fromFile:fileData] + val;
                    break;
                }
                case BIND_OPCODE_ADD_ADDR_ULEB:{
                    unsigned long long val = [self readULEB128:range fromFile:fileData];
                    address += val;
                    break;
                }
                case BIND_OPCODE_DO_BIND:{
                    [bindInfoDic setObject:symbolName forKey:@(address)];
                    address += 8;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:{
                    unsigned long long val = [self readULEB128:range fromFile:fileData];
                    [bindInfoDic setObject:symbolName forKey:@(address)];

                    address += 8 + val;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:{
                    uint32_t scale = immediate;
                    [bindInfoDic setObject:symbolName forKey:@(address)];

                    address += 8 + scale * 8;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:{
                    unsigned long long count = [self readULEB128:range fromFile:fileData];
                    unsigned long long skip = [self readULEB128:range fromFile:fileData];
                    for (unsigned long long index = 0; index < count; index++){
                        [bindInfoDic setObject:symbolName forKey:@(address)];

                        address += 8 + skip;
                    }
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:{
                    dylibIndex = immediate;
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:{
                    dylibIndex = [self readULEB128:range fromFile:fileData];
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:{
                    if (immediate == 0){
                        dylibIndex = 0;
                    }else{
                        int8_t signExtended = immediate | BIND_OPCODE_MASK;
                        dylibIndex = signExtended;
                    }
                    break;
                }
                case BIND_OPCODE_SET_TYPE_IMM:{
                    //bind type
                    break;
                }
                case BIND_OPCODE_SET_ADDEND_SLEB:{
                    //addend
                    [self readSLEB128:range fromFile:fileData];
                    break;
                }
                default:
                    [NSException raise:@"Bind info" format:@"Unknown opcode (%u %u)",
                     ((uint32_t)-1 & opcode), ((uint32_t)-1 & immediate)];
            }
        }
    }
    return bindInfoDic;
}

+ (unsigned long long)getOffsetFromVmAddress:(unsigned long long )address fileData:(NSData *)fileData{
    
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            if (address >= segmentCommand.vmaddr && address <= segmentCommand.vmaddr + segmentCommand.vmsize) {
                free(cmd);
                return address - (segmentCommand.vmaddr - segmentCommand.fileoff);
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    return address;
}

//judge whether the file is supported
+ (BOOL)isSupport:(NSData *)fileData {
    
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    switch (magic) {
        case FAT_MAGIC: //fat binary file
        case FAT_CIGAM:
        case FAT_MAGIC_64:
        case FAT_CIGAM_64:
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

+ (BOOL)isMachO:(NSData *)fileData {
    
    uint32_t magic = *(uint32_t*)((uint8_t *)[fileData bytes]);
    switch (magic) {
        case FAT_MAGIC: //fat binary file
        case FAT_CIGAM:
        case FAT_MAGIC_64:
        case FAT_CIGAM_64:
        case MH_MAGIC: //32 bit mach-o
        case MH_CIGAM:
        case MH_MAGIC_64://64 bit mach-o
        case MH_CIGAM_64:
        {
            //a single object
            return YES;
        } break;
        default:
        {
            //it is a static library
            if (*(uint64_t*)((uint8_t *)[fileData bytes]) == *(uint64_t*)"!<arch>\n") {
                //                NSLog(@"符合单架构静态库特征");
                return YES;
            }
        }
    }
    return NO;
}

+ (SwiftKind)getSwiftType:(SwiftType)type{
    //读低五位判断类型
    if ((type.Flag & 0x1f) == SwiftKindClass) {
        return SwiftKindClass;
    }else if ((type.Flag & 0x3) == SwiftKindProtocol){
        return SwiftKindProtocol;
    }else if((type.Flag & 0x1f) == SwiftKindStruct){
        return SwiftKindStruct;
    }else if((type.Flag & 0x1f) == SwiftKindEnum){
        return SwiftKindEnum;
    }else if((type.Flag & 0x0f) == SwiftKindModule){
        return SwiftKindModule;
    }
    
    return SwiftKindUnknown;
}

+ (BOOL)hasVTable:(SwiftType)type{
    if ((type.Flag & 0x80000000) == 0x80000000) {return YES;}
    
    return NO;
}

+ (BOOL)hadOverrideTable:(SwiftType)type{
    if ((type.Flag & 0x40000000) == 0x40000000) {return YES;}
    return NO;
}

+ (SwiftMethodKind)getSwiftMethodKind:(SwiftMethod)method{
    SwiftMethodKind kind = (SwiftMethodKind)(method.Flag&SwiftMethodTypeKind);
    return kind;
}

+ (SwiftMethodType)getSwiftMethodType:(SwiftMethod)method{
    SwiftMethodType type = SwiftMethodTypeKind;
    if ((method.Flag&SwiftMethodTypeInstance) == SwiftMethodTypeInstance) {
        type = SwiftMethodTypeInstance;
    }else if ((method.Flag&SwiftMethodTypeDynamic) == SwiftMethodTypeDynamic){
        type = SwiftMethodTypeDynamic;
    }else if ((method.Flag&SwiftMethodTypeExtraDiscriminator) == SwiftMethodTypeExtraDiscriminator){
        type = SwiftMethodTypeExtraDiscriminator;
    }
    return type;
}

+ (NSString *)getSwiftTypeNameWithSwiftType:(SwiftType)type Offset:(uintptr_t)offset vm:(uintptr_t)vm fileData:(NSData*)fileData{
    SwiftKind kindType = [WBBladesTool getSwiftType:type];
    
    uintptr_t typeNameOffset = 0;
    uintptr_t typeParent = 0;
    if (kindType == SwiftKindClass) {
        SwiftClassType classType = {0};
        NSRange range = NSMakeRange(offset, 0);
        NSData *data = [WBBladesTool readBytes:range length:sizeof(SwiftClassType) fromFile:fileData];
        [data getBytes:&classType length:sizeof(SwiftClassType)];
        
        typeNameOffset = classType.Name;
        typeParent = offset + 4 + classType.Parent;
    }else if(kindType == SwiftKindStruct){
        SwiftStructType structType = {0};
        NSRange range = NSMakeRange(offset, 0);
        NSData *data = [WBBladesTool readBytes:range length:sizeof(SwiftStructType) fromFile:fileData];
        [data getBytes:&structType length:sizeof(SwiftStructType)];
        
        typeNameOffset = structType.Name;
        typeParent = offset + 4 + structType.Parent;
    }else if(kindType == SwiftKindEnum){
        SwiftEnumType enumType = {0};
        NSRange range = NSMakeRange(offset, 0);
        NSData *data = [WBBladesTool readBytes:range length:sizeof(SwiftEnumType) fromFile:fileData];
        [data getBytes:&enumType length:sizeof(SwiftEnumType)];
        
        typeNameOffset = enumType.Name;
        typeParent = offset + 4 + enumType.Parent;
    }else if(kindType == SwiftKindProtocol){
        SwiftProtocolType protosType = {0};
        NSRange range = NSMakeRange(offset, 0);
        NSData *data = [WBBladesTool readBytes:range length:sizeof(SwiftProtocolType) fromFile:fileData];
        [data getBytes:&protosType range:NSMakeRange(0, sizeof(SwiftProtocolType))];
        
        typeNameOffset = protosType.Name;
        typeParent = offset + 4 + protosType.Parent;
    }
    
    uintptr_t  nameOffset = offset + 8 + typeNameOffset;
    
    if (nameOffset > fileData.length) {
        return @"";
    }
    
    uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
    [fileData getBytes:buffer range:NSMakeRange(nameOffset, CLASSNAME_MAX_LEN)];
    NSString *typeName = NSSTRING(buffer);
    free(buffer);
    
    if (typeParent > vm) {
        typeParent = typeParent - vm;
    }
    
    SwiftType parentType = {0};
    NSRange range = NSMakeRange(typeParent, 0);
    NSData *data = [WBBladesTool readBytes:range length:sizeof(SwiftType) fromFile:fileData];
    [data getBytes:&parentType length:sizeof(SwiftType)];
    
    SwiftKind parentKindType = [WBBladesTool getSwiftType:parentType];
    if (parentKindType != SwiftKindUnknown) {
       NSString *parentName = [self getSwiftTypeNameWithSwiftType:parentType Offset:typeParent vm:vm fileData:fileData];
        if (parentName && parentName.length > 0) {
            typeName = [NSString stringWithFormat:@"%@.%@",parentName,typeName];
        }
    }
    
    return typeName;
}

+ (SwiftProtocolTableKind)getSwiftProtocolTableKind:(SwiftMethod)method{
    SwiftProtocolTableKind kind = (SwiftProtocolTableKind)(method.Flag&SwiftProtocolTableTypeKind);
    return kind;
}

+ (SwiftProtocolTableType)getSwiftProtocolTableType:(SwiftMethod)method{
    SwiftProtocolTableType type = SwiftProtocolTableTypeKind;
    if ((method.Flag&SwiftProtocolTableTypeInstance) == SwiftProtocolTableTypeInstance) {
        type = SwiftProtocolTableTypeInstance;
    }else if ((method.Flag&SwiftProtocolTableTypeExtraDiscriminatorShift) == SwiftProtocolTableTypeExtraDiscriminatorShift){
        type = SwiftProtocolTableTypeExtraDiscriminatorShift;
    }else if ((method.Flag&SwiftProtocolTableTypeExtraDiscriminator) == SwiftProtocolTableTypeExtraDiscriminator){
        type = SwiftProtocolTableTypeExtraDiscriminator;
    }
    return type;
}

+ (NSString *)getDemangleName:(NSString *)mangleName{
    int (*swift_demangle_getDemangledName)(const char *,char *,int ) = (int (*)(const char *,char *,int))dlsym(RTLD_DEFAULT, "swift_demangle_getDemangledName");
    
    if (swift_demangle_getDemangledName) {
        char *demangleName = (char *)malloc(CLASSNAME_MAX_LEN + 1);
        int length = CLASSNAME_MAX_LEN + 1;
        swift_demangle_getDemangledName([mangleName UTF8String],demangleName,length);
        NSString *demangleNameStr = [NSString stringWithFormat:@"%s",demangleName];
        free(demangleName);
        return demangleNameStr;
    }
    return mangleName;
}

+ (void*)mallocReversalData:(uintptr_t)data length:(int)length{
    char *result = (char *)malloc(length);
    memset(result, 0, length);
    void *ptr1 = NULL;
    uintptr_t ptr2 = NULL;

    for (uintptr_t i = 0; i < length; i++) {
        ptr1 = result + i;
        ptr2 = data + (length - i - 1);
        
        memset(ptr1, (UInt8)*(char*)ptr2, 1);
    }
    
    return result;
}

@end
