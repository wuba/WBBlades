//
//  WBBladesTool.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/12/30.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesTool.h"
#import "WBBladesDefines.h"
#import <mach-o/fat.h>
#import <dlfcn.h>
#import <string.h>
#import "ChainFixUpsHelper.h"

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
    NSString *str = nil;
    if (range.location < fileData.length) {
        str = @((char *)[fileData bytes] + range.location);
    }else {
        return str;
    }
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
    if(NSMaxRange(range) > fileData.length) {
        return nil;
    }
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
    IMP imp = [orig methodForSelector:sel];
    unichar (*charAtIdx)(id, SEL, NSUInteger) = (unichar (*)(id, SEL, NSUInteger))imp;
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

+ (NSArray *)disassemWithMachOFile:(NSData *)fileData  from:(unsigned long long)begin length:(unsigned long long )size accfunDic:(NSDictionary *)accfunDic {
    
    NSMutableArray * addressReferenceInCode = [NSMutableArray array];
    
    // Get compilation.
    csh cs_handle = 0;
    cs_err cserr;
    if ((cserr = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cs_handle)) != CS_ERR_OK ) {
        NSLog(@"Failed to initialize Capstone: %d, %s.", cserr, cs_strerror(cs_errno(cs_handle)));
        return NULL;
    }
    // Set the parsing mode.
    cs_option(cs_handle, CS_OPT_MODE, CS_MODE_ARM);
    //        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    //总的指令数
    unsigned long long total_count = size / 4;
    // 最大循环次数，实际不能超过这个数+1
    unsigned long long MaxStep = 256;
    // 每次处理指令最大数，实际可能超过这个数
    unsigned long long MaxEachCount = 256;
    // 实际每次处理的指令数
    unsigned long long each_step_count = 0;
    // 实际需要循环step次去处理
    unsigned long long step = 0;
    if ((total_count / MaxEachCount) > MaxStep) {
        each_step_count = total_count / MaxStep;
        step = MaxStep;
        // 如果不能整除，则再加一次循环，以免末尾的一些指令遗漏
        if ((total_count % MaxEachCount) > 0) {
            step++;
        }
    }
    else {
        each_step_count = MaxEachCount;
        step = total_count / MaxEachCount;
        // 如果不能整除，则再加一次循环，以免末尾的一些指令遗漏
        if ((total_count % MaxEachCount) > 0) {
            step++;
        }
    }
    
//    static cs_insn* tmp[256];
//    static size_t tmp_count[256];
    
    NSMutableDictionary * tmpDict  = [NSMutableDictionary dictionary];
    dispatch_apply(step, dispatch_get_global_queue(0, 0), ^(size_t index) {
        cs_insn *cs_insn = NULL;
        char *ot_sect = (char *)[fileData bytes] + begin + index * each_step_count * 4;
        uint64_t ot_addr = begin + index * each_step_count * 4;
        unsigned long long ins_size  = 0;
        if ((index + 1) * each_step_count * 4 <= size && step > 0) {
            ins_size = each_step_count * 4;
        }
        else {
            ins_size = (size - index * each_step_count * 4);// 最后那次循环可能指令数达不到each_step_count
        }
//        (index < 255)?step*4:(size - step * 255 * 4);
        // Disassemble
        size_t disasm_count = cs_disasm(cs_handle, (const uint8_t *)ot_sect, ins_size, ot_addr, 0, &cs_insn);
        
        NSUInteger startIndex = index * each_step_count;
        NSMutableArray * referenceInCode = [NSMutableArray array];
        for (NSUInteger i=0; i<disasm_count; i++) {
            @autoreleasepool {
//                struct cs_insn s_cs_insn = cs_insn[i];
                char *dataStr = cs_insn[i].op_str;
                char *asmstr = cs_insn[i].mnemonic;
//                if (strcmp(".byte",asmstr) == 0) {
//                    continue;
//                }
//                if (strcmp("ret",asmstr) == 0 ) {
//                    [referenceInCode addObject:[[NSString stringWithCString:asmstr encoding:NSUTF8StringEncoding] stringByAppendingFormat:@":%lu",startIndex + i]];
//                    continue;
//                }
//                if (strcmp("stp",asmstr) == 0) {
////                    连续的stp只保留第1条
//                    if (referenceInCode.count > 0) {
//                        NSString *preASM = referenceInCode.lastObject;
//                        if ([preASM containsString:@"stp:"]) {
//                            continue;
//                        }
//                        else {
//                            [referenceInCode addObject:[[NSString stringWithCString:asmstr encoding:NSUTF8StringEncoding] stringByAppendingFormat:@":%lu",startIndex + i]];
//                        }
//                    }
//                    else {
//                        [referenceInCode addObject:[[NSString stringWithCString:asmstr encoding:NSUTF8StringEncoding] stringByAppendingFormat:@":%lu",startIndex + i]];
//                    }
//                    continue;
//                }
////                if (!strstr(dataStr, "#0x")) {
////                    continue;
////                }
                if (strcmp("bl",asmstr) == 0) {
                    NSString *addrStr = [NSString stringWithFormat:@"%s", dataStr];
                    // 指令数组中仅存储accessfunction中存在的bl，也就是指令数组中都是有对应swift类的bl指令
                    if (accfunDic[addrStr]) {
                        NSString *blStr = [NSString stringWithFormat:@"%s %s", asmstr, dataStr];
                        [referenceInCode addObject:[NSString stringWithFormat:@"%@:%lu", blStr, startIndex + i]];
                    }
                    continue;
                }
                
            }
        }
        free(cs_insn);
        if (referenceInCode.count>0) {
            @synchronized (tmpDict) {
                tmpDict[[NSString stringWithFormat:@"%ld",index]] = referenceInCode;
            }
        }else{
            NSLog(@"cs_disasm error");
        }
    });
    // 将每次循环得到的数组整合起来
    for (NSString *key in tmpDict.allKeys) {
        NSArray *sub_address = tmpDict[key];
        [addressReferenceInCode addObjectsFromArray:sub_address];
    }
    // “bl #0x77bc:50”，对addressReferenceInCode中的指令按所在下标大小进行排序
    NSArray *assemResult = [addressReferenceInCode sortedArrayUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        NSArray *arr1 = [(NSString *)obj1 componentsSeparatedByString:@":"];
        NSArray *arr2 = [(NSString *)obj2 componentsSeparatedByString:@":"];
        if ([arr1[1] integerValue] > [arr2[1] integerValue]) {
            return NSOrderedDescending;
        }
        else {
            return NSOrderedAscending;
        }
    }];
    return assemResult;
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

+ (NSArray *)dylibNamesFromFile:(NSData *)fileData {
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    NSMutableArray *dylibNames = [@[] mutableCopy];
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB || LC_LOAD_UPWARD_DYLIB == cmd->cmd || LC_LOAD_DYLINKER == cmd->cmd){
            //记录外部依赖的动态库
            struct dylib_command dylibs;
            [fileData getBytes:&dylibs range:NSMakeRange(currentLcLocation, sizeof(dylibs))];
            uint8_t *dylid_name = (uint8_t *)malloc(150);
            [fileData getBytes:dylid_name range:NSMakeRange(currentLcLocation +dylibs.dylib.name.offset, 150)];
            NSString *dylid_name_string = [NSString stringWithFormat:@"%s",dylid_name];
            [dylibNames addObject:dylid_name_string];
            free(dylid_name);
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    return [dylibNames copy];
}

+ (NSDictionary *)dynamicBindingInfoFromFile:(NSData *)fileData{
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    dyld_info_command dyldInfoCmd = {0};
    NSMutableArray *dylibNames = [@[] mutableCopy];
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        if (cmd->cmd == LC_DYLD_INFO ||
            cmd->cmd == LC_DYLD_INFO_ONLY) {
            dyld_info_command segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(dyld_info_command))];
            dyldInfoCmd = segmentCommand;
        }else if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB || LC_LOAD_UPWARD_DYLIB == cmd->cmd || LC_LOAD_DYLINKER == cmd->cmd){
            //记录外部依赖的动态库
            struct dylib_command dylibs;
            [fileData getBytes:&dylibs range:NSMakeRange(currentLcLocation, sizeof(dylibs))];
            uint8_t *dylid_name = (uint8_t *)malloc(150);
            [fileData getBytes:dylid_name range:NSMakeRange(currentLcLocation +dylibs.dylib.name.offset, 150)];
            NSString *dylid_name_string = [NSString stringWithFormat:@"%s",dylid_name];
            [dylibNames addObject:dylid_name_string];
            free(dylid_name);
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }

    NSMutableDictionary *allBindInfoDic = [NSMutableDictionary dictionary];
    NSDictionary *bindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.bind_off size:dyldInfoCmd.bind_size isLazyBind:NO fromFile:fileData dylibNames:[dylibNames copy]];
    NSDictionary *weakBindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.weak_bind_off size:dyldInfoCmd.weak_bind_size isLazyBind:NO fromFile:fileData dylibNames: dylibNames];
    NSDictionary *lazyBindInfoDic = [self dynamicBindingInfoWithOffset:dyldInfoCmd.lazy_bind_off size:dyldInfoCmd.lazy_bind_size isLazyBind:YES fromFile:fileData dylibNames: dylibNames];
    [allBindInfoDic addEntriesFromDictionary:bindInfoDic];
    [allBindInfoDic addEntriesFromDictionary:weakBindInfoDic];
    [allBindInfoDic addEntriesFromDictionary:lazyBindInfoDic];
    return allBindInfoDic.copy;
}


+ (NSDictionary *)dynamicBindingInfoWithOffset:(unsigned long long)offset size:(unsigned long long)size isLazyBind:(BOOL)isLazyBind fromFile:(NSData *)fileData dylibNames:(NSArray *)dylibNames{

    NSMutableDictionary *bindInfoDic = [NSMutableDictionary dictionary];
    //code from macoview
    uint8_t byte;
    BOOL end = NO;
    unsigned long long address = 0;
    NSString *symbolName = @"";
    NSString *dylibName = @"";
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
                    end = isLazyBind?YES:NO;
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
                    [bindInfoDic setObject:@{@"symbolName":symbolName, @"dylibName": dylibName} forKey:@(address)];
                    address += 8;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:{
                    unsigned long long val = [self readULEB128:range fromFile:fileData];
                    [bindInfoDic setObject:@{@"symbolName":symbolName, @"dylibName": dylibName} forKey:@(address)];

                    address += 8 + val;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:{
                    uint32_t scale = immediate;
                    [bindInfoDic setObject:@{@"symbolName":symbolName, @"dylibName": dylibName} forKey:@(address)];

                    address += 8 + scale * 8;
                    break;
                }
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:{
                    unsigned long long count = [self readULEB128:range fromFile:fileData];
                    unsigned long long skip = [self readULEB128:range fromFile:fileData];
                    for (unsigned long long index = 0; index < count; index++){
                        [bindInfoDic setObject:@{@"symbolName":symbolName, @"dylibName": dylibName} forKey:@(address)];

                        address += 8 + skip;
                    }
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:{
                    dylibIndex = immediate;
                    if (dylibIndex <=   dylibNames.count) {
                        dylibName = dylibNames[dylibIndex - 1];
                    }
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:{
                    dylibIndex = [self readULEB128:range fromFile:fileData];
                    if (dylibIndex <=   dylibNames.count) {
                        dylibName = dylibNames[dylibIndex - 1];
                    }
                    break;
                }
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:{
                    if (immediate == 0){
                        dylibIndex = 0;
                        if (dylibIndex <=   dylibNames.count) {
                            dylibName = dylibNames[dylibIndex - 1];
                        }
                    }else{
                        int8_t signExtended = immediate | BIND_OPCODE_MASK;
                        dylibIndex = signExtended;
                        if (dylibIndex <=  dylibNames.count) {
                            dylibName = dylibNames[dylibIndex - 1];
                        }
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
                    break;
//                    [NSException raise:@"Bind info" format:@"Unknown opcode (%u %u)",
//                     ((uint32_t)-1 & opcode), ((uint32_t)-1 & immediate)];
            }
        }
    }
    return bindInfoDic;
}

+ (unsigned long long)getSectionMigrateOffset:(unsigned long long)address andBaseAddr:(unsigned long long)vm fileData:(NSData *)fileData{
    address += vm;
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
                return segmentCommand.vmaddr - segmentCommand.fileoff - vm;
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    return address;
}

+ (unsigned long long)getOffsetFromVmAddress:(unsigned long long )address fileData:(NSData *)fileData{

    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    BOOL chainFixUps = [ChainFixUpsHelper shareInstance].isChainFixups;
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            if (address >= segmentCommand.vmaddr && address <= segmentCommand.vmaddr + segmentCommand.vmsize) {
                free(cmd);
                unsigned long long  returnValue = (address - (segmentCommand.vmaddr - segmentCommand.fileoff));
                return chainFixUps?(returnValue & ChainFixUpsRawvalueMask):returnValue;
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    unsigned long long  returnValue = address;
    return chainFixUps?(returnValue & ChainFixUpsRawvalueMask):returnValue;;
}

+ (section_64)getTEXTConst:(unsigned long long )address fileData:(NSData *)fileData{

    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    section_64 textConst = {0};
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command cmd;// (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:&cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        if (cmd.cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            if (address >= segmentCommand.vmaddr && address <= segmentCommand.vmaddr + segmentCommand.vmsize) {
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                int sectionNum = 1;
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    if (address >= sectionHeader.addr && address < sectionHeader.addr + sectionHeader.size) {
                        return sectionHeader;
                    }
                    currentSecLocation += sizeof(section_64);
                    sectionNum++;
                }
            }
        }
        currentLcLocation += cmd.cmdsize;
    }

    return textConst;
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
            NSLog(@"32位 Mach-O");
        } break;

        case MH_MAGIC_64://64 bit mach-o
        case MH_CIGAM_64:
        {
            //a single object
            NSLog(@"64位 Mach-O");
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
    }else if((type.Flag & 0x1f) == SwiftKindModule){
        return SwiftKindModule;
    }else if((type.Flag & 0x1f) == SwiftKindAnonymous){
        return SwiftKindAnonymous;
    }else if((type.Flag & 0x1f) == SwiftKindOpaqueType){
        return SwiftKindOpaqueType;
    }

    return SwiftKindUnknown;
}

+ (BOOL)hasVTable:(SwiftType)type{
    if ((type.Flag & 0x80000000) == 0x80000000) {return YES;}
    return NO;
}

+ (BOOL)hasOverrideTable:(SwiftType)type{
    if ((type.Flag & 0x40000000) == 0x40000000) {return YES;}
    return NO;
}
+ (BOOL)hasSingletonMetadataInitialization:(SwiftType)type{
    if ( (type.Flag & 0x00010000 )) {return YES;}
    return NO;
}

+ (BOOL)isGeneric:(SwiftType)type{
    if ( (type.Flag & 0x80 )) {return YES;}
    return NO;
}

+ (BOOL)isGenericType:(SwiftBaseType)type{
    if ( (type.Flag & 0x80 )) {return YES;}
    return NO;
}

+ (BOOL)hasResilientSuperclass:(SwiftType)type{
    if ((type.Flag & 0x20000000) == 0x20000000) {return YES;}
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
    uintptr_t typeNameOffset_new = [WBBladesTool getOffsetFromVmAddress:typeNameOffset fileData:fileData];

    uintptr_t  typeAddress = offset + 8 + typeNameOffset_new;//
    uintptr_t nameOffset = [WBBladesTool getOffsetFromVmAddress:typeAddress fileData:fileData];

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
    if (typeParent > 0 && parentKindType != SwiftKindModule) {
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
        char *demangleName = (char *)malloc(201);
        memset(demangleName, 0, 201);
        int length = 201;
        swift_demangle_getDemangledName([mangleName UTF8String],demangleName,length);
        NSString *demangleNameStr = [NSString stringWithFormat:@"%s",demangleName];
        free(demangleName);
        return demangleNameStr.length>0?demangleNameStr:mangleName;
    }
    NSAssert(swift_demangle_getDemangledName, @"在 Build Phases -> Link Binary with Libraries 中 加入 libswiftDemangle.tbd");
    return mangleName;
}

+ (NSString *)getDemangleNameWithCString:(char *)mangleName{
    int (*swift_demangle_getDemangledName)(const char *,char *,int ) = (int (*)(const char *,char *,int))dlsym(RTLD_DEFAULT, "swift_demangle_getDemangledName");

    if (swift_demangle_getDemangledName) {
        char *demangleName = (char *)malloc(201);
        int length = 201;
        swift_demangle_getDemangledName(mangleName,demangleName,length);
        NSString *demangleNameStr = [NSString stringWithFormat:@"%s",demangleName];
        free(demangleName);
        return demangleNameStr;
    }
    NSAssert(swift_demangle_getDemangledName, @"在 Build Phases -> Link Binary with Libraries 中 加入 libswiftDemangle.tbd");
    return [NSString stringWithFormat:@"%s",mangleName];
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

/**
 addMetadataInstantiationCache -> 4B  (class only)
 addMetadataInstantiationPattern -> 4B  (class only)
 GenericParamCount -> 2B
 GenericRequirementCount -> 2B
 GenericKeyArgumentCount -> 2B
 GenericExtraArgumentCount -> 2B
 params -> paramsCount B
 pandding -> pandding B
 3 * 4 * (requeireCount) B
 */
+ (short)addPlaceholderWithGeneric:(unsigned long long)typeOffset fileData:(NSData*)fileData{

    SwiftType swiftType;
    [fileData getBytes:&swiftType range:NSMakeRange(typeOffset, sizeof(SwiftType))];

    if (![self isGeneric:swiftType]) {
        return 0;
    }
    //非class | Anonymous不处理
    int front = 0;
    //Anonymous的header为8字节
    int header = 8;
    if ([self getSwiftType:swiftType] == SwiftKindClass) {
        //class的11个（4B） + addMetadataInstantiationCache （4B） + addMetadataInstantiationPattern（4B）
        front = (11 + 2) * 4;
        //class的header为16字节
        header = 16;
    }else if ([self getSwiftType:swiftType] == SwiftKindAnonymous){
        front = 2 * 4;
    }else{
        return 0;
    }

    short paramsCount = 0;
    short requeireCount = 0;

    [fileData getBytes:&paramsCount range:NSMakeRange(typeOffset + front, sizeof(short))];
    [fileData getBytes:&requeireCount range:NSMakeRange(typeOffset + front + 2, sizeof(short))];

    //4字节对齐
    short pandding = (unsigned)-paramsCount & 3;

    return (header  + paramsCount + pandding + 3 * 4 * (requeireCount));
//    return (16 + paramsCount + pandding + 3 * 4 * (requeireCount) + 4);

}

+ (BOOL)anonymousHasMangledName:(SwiftType)baseType{
    if ((baseType.Flag & 0xFFFF) == 0x01) {
        return YES;
    }
    return NO;
}

+ (uintptr_t)methodNumLocation:(SwiftType)baseType offset:(uintptr_t)typeOffset fileData:(NSData *)fileData{
    //遍历Vtable和overrideTable
    BOOL hasVtable = [self hasVTable:baseType];
    BOOL hasOverrideTable = [self hasOverrideTable:baseType];
    BOOL hasSingletonMetadataInitialization = [self hasSingletonMetadataInitialization:baseType];
    BOOL hasResilientSuperclass = [self hasResilientSuperclass:baseType];
    short genericSize = [self addPlaceholderWithGeneric:typeOffset fileData:fileData];
    if (!hasVtable && !hasOverrideTable ) {return typeOffset + sizeof(SwiftClassTypeNoMethods);}
    uintptr_t typeLocation = typeOffset + sizeof(struct SwiftClassTypeNoMethods) + genericSize + (hasResilientSuperclass?4:0)+ (hasSingletonMetadataInitialization?12:0) + (hasVtable?4:0);
    return typeLocation;
}

+ (UInt32)sectionFlagsWithIndex:(int)index fileData:(NSData *)fileData{

    static NSMutableDictionary *sectionDic = @{}.mutableCopy;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        mach_header_64 mhHeader;
        [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
        unsigned long long currentLcLocation = sizeof(mach_header_64);
        int sectionNum = 1;
        for (int i = 0; i < mhHeader.ncmds; i++) {
            load_command* cmd = (load_command *)malloc(sizeof(load_command));
            [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

            if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
                segment_command_64 segmentCommand;
                [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    currentSecLocation += sizeof(section_64);
                    [sectionDic setObject:@(sectionHeader.flags) forKey:@(sectionNum)];
                    sectionNum++;
                }
            }
            currentLcLocation += cmd->cmdsize;
            free(cmd);
        }
    });
    return [[sectionDic objectForKey:@(index)] unsignedIntValue];
}

@end

