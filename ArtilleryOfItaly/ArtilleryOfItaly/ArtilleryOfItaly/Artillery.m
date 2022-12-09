//
//  Artillery.m
//  ArtilleryOfItaly
//
//  Created by 皮拉夫大王 on 2021/5/14.
//

#import "Artillery.h"
#import "../dwarf.h"
#import "ArtilleryModels.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>

#define mach_header_64 struct mach_header_64
#define load_command struct load_command
#define symtab_command struct symtab_command
#define segment_command_64 struct segment_command_64
#define section_64 struct section_64
#define MACHO_PATH_LEN 2000
#define LOADADDR 0x100000000


@implementation Artillery

#pragma mark 定义
struct SrcFilesData {
    char ** srcfiles;
    Dwarf_Signed srcfilescount;
    int srcfilesres;
};

static Dwarf_Signed symbolsCount = 0;
static NSData *fileData;
static NSString *outPath;

#pragma mark 工具方法
static void getNumber(Dwarf_Attribute attr,Dwarf_Unsigned *val){
    Dwarf_Error error = 0;
    int res;
    Dwarf_Signed sval = 0;
    Dwarf_Unsigned uval = 0;
    Dwarf_Error *errp  = 0;
    errp = &error;
    res = dwarf_formudata(attr,&uval,errp);
    if(res == DW_DLV_OK) {
        *val = uval;
        
        return;
    }
    res = dwarf_formsdata(attr,&sval,errp);
    if(res == DW_DLV_OK) {
        *val = sval;
        return;
    }
    return;
}

static void getString(Dwarf_Debug dbg, Dwarf_Attribute attr,char ** stringval){
    Dwarf_Error error = 0;
    int res;
    Dwarf_Error *errp  = 0;
    errp = &error;
    
    res = dwarf_formstring(attr, stringval, errp);
    if(res != DW_DLV_OK) {
        printf("Error !\n");
        return;
    }
    return;
}

static void getAddr(Dwarf_Attribute attr,Dwarf_Addr *val){
    Dwarf_Error error = 0;
    int res;
    Dwarf_Addr uval = 0;
    Dwarf_Error *errp  = 0;
    errp = &error;
    
    res = dwarf_formaddr(attr,&uval,errp);
    if(res == DW_DLV_OK) {
        *val = uval;
        return;
    }
    res = dwarf_formudata(attr, &uval, errp);
    if(res == DW_DLV_OK) {
        *val = uval;
        return;
    }
    Dwarf_Signed sival = 0;
    res = dwarf_formsdata(attr, &sival, errp);
    if(res == DW_DLV_OK) {
        *val = sival;
        return;
    }
    
    return;
}
static void resetSrcfiles(Dwarf_Debug dbg,struct SrcFilesData *sf){
    Dwarf_Signed sri = 0;
    if (sf->srcfiles) {
        for (sri = 0; sri < sf->srcfilescount; ++sri) {
            dwarf_dealloc(dbg, sf->srcfiles[sri],
                          DW_DLA_STRING);
        }
        dwarf_dealloc(dbg, sf->srcfiles, DW_DLA_LIST);
    }
    sf->srcfilesres = DW_DLV_ERROR;
    sf->srcfiles = 0;
    sf->srcfilescount = 0;
}

static NSString* getUUID(){
    
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    UInt64 currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_UUID) {
            
            struct uuid_command uuidCommand;
            [fileData getBytes:&uuidCommand range:NSMakeRange(currentLcLocation, sizeof( struct uuid_command))];
            NSString *uuid = @"";
            for (int i = 0 ; i < 16; i++) {
                uuid = [uuid stringByAppendingFormat:@"%02x",uuidCommand.uuid[i]];
            }
            free(cmd);
            return uuid;
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    return @"";
}

//static BOOL isCharacter(NSString *string) {
//    //由于NSString中有全角符号和半角符号, 因此有些符号要包括全角和半角的
//    NSString *regex = @"~`!@#$%^&*()_+-=[]|{};':\",./<>?]{,}/：；（）¥「」＂、\\|~＜＞€^•'";
//    NSInteger str_length = [string length];
//    NSInteger allIndex = 0;
//    for (int i = 0; i<str_length; i++) {
//        NSString *subStr = [string substringWithRange:NSMakeRange(i, 1)];
//        if([regex rangeOfString:subStr].location != NSNotFound){
//            //存在
//            allIndex++;
//        }
//    }
//
//    if (str_length == allIndex) {
//        return YES;
//    } else {
//        return NO;
//    }
//}


//是否是字母或数字
static BOOL isNumAndLetterCharSet(NSString *string) {
    if (string.length == 0) {
        return NO;
    } else {
        NSCharacterSet *numAndLetterCharSet = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
        return ([string rangeOfCharacterFromSet:numAndLetterCharSet].location == NSNotFound);
    }
}

static NSString* transMainFunc(NSString *string) {
    NSString *newString = nil;
    if ([string containsString:@"main.m"] && [string containsString:@"main"]) {
        NSString *tempString = [string stringByTrimmingCharactersInSet:(NSCharacterSet.whitespaceCharacterSet)];
        NSArray *tempStrArr = [tempString componentsSeparatedByString:@"\n"];
        for (NSString *tempSymbol in tempStrArr) {
            NSArray *symbols = [tempSymbol componentsSeparatedByString:@"\t"];

            if (symbols.count > 2 && [symbols[2] containsString:@"main"]) {
                NSArray *mainFuncs = [symbols[2] componentsSeparatedByString:@"main"];
                NSString *mainBefore = mainFuncs[0];
                NSString *mainAfter = mainFuncs[1];
                //如果main前/后面不是字母或者数字
                if (!isNumAndLetterCharSet(mainBefore) && !(isNumAndLetterCharSet(mainAfter))) {
                    NSString *symbol = [NSString stringWithFormat:@"wbSymbol(main)\t%@",symbols[3]];
                    NSString *aString = [NSString stringWithFormat:@"%@\t%@\t%@\n",symbols[0],symbols[1],symbol];
                    if (newString) {
                        newString = [NSString stringWithFormat:@"%@%@",newString,aString];
                    } else {
                        newString = aString;
                    }
                }
            }
        }
    }
    return newString;
}

static void writefile(NSString *string ,NSString *filePath){
    
    if (transMainFunc(string)) {
        string = transMainFunc(string);
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if(![fileManager fileExistsAtPath:filePath]){
        NSString *str = @"";
        [str writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:filePath];
    [fileHandle seekToEndOfFile];  //将节点跳到文件的末尾
    NSData* stringData  = [string dataUsingEncoding:NSUTF8StringEncoding];
    [fileHandle writeData:stringData]; //追加写入数据
    [fileHandle closeFile];
}
#pragma mark 流程
+ (void)readDwarf:(NSString*)dwarfPath outputPath:(NSString*)ouput{
    
    outPath = ouput;
    Dwarf_Debug dbg = [self getDebug:dwarfPath];
    if (dbg) {
        fileData = [NSData dataWithContentsOfFile:dwarfPath options:NSDataReadingMappedIfSafe error:NULL];
    }
    if (!fileData) {
        NSLog(@"file read error!");
        return;
    }
    //获取符号表并排序
    NSArray *symbols = [self getSortedSymbolList:fileData];
    
    Dwarf_Error error = 0;
    Dwarf_Signed count = 0;
    static Dwarf_Type *types = NULL;
    dwarf_get_pubtypes(dbg, &types, &count, &error);
    
    NSString *header = [NSString stringWithFormat:@"UUID:\%@\nSymbol table:\n",getUUID()] ;
    [header writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    
    //遍历编译单元列表
    [self readCUList:dbg];
    
    [self writeSymbols:symbols];
    
    dwarf_types_dealloc(dbg, types, count);
    dwarf_finish(dbg);
    fileData = nil;
    outPath = nil;
}

+ (Dwarf_Debug)getDebug:(NSString *)filepath{
    Dwarf_Debug dbg = 0;
//    char realPath[MACHO_PATH_LEN];
//    realPath[0] = 0;
    int res = DW_DLV_ERROR;
    
    res = dwarf_init_path(filepath.UTF8String,
                          0,
                          0,
                          DW_GROUPNUMBER_ANY,0,0,&dbg,NULL);
    if(res != DW_DLV_OK) {
        dbg = 0;
    }
    
    return dbg;
}

//基于libdwarf simplereader.c做的修改
+ (void)readCUList:(Dwarf_Debug)dbg{
    
    while (YES) {
        @autoreleasepool {
            
            Dwarf_Unsigned headerLength;/*cu_header_length*/
            Dwarf_Half versionStamp;     /*version_stamp*/
            Dwarf_Off abbrevOffset;      /*abbrev_offset*/
            Dwarf_Half addressSize;     /*address_size*/
            Dwarf_Half lengthSize;     /*length_size*/
            Dwarf_Half extensionSize;     /*extension_size*/
            Dwarf_Sig8 signature;    /*type signature*/
            Dwarf_Unsigned typeoffset; /*typeoffset*/
            Dwarf_Unsigned nextHeaderOff; /*next_cu_header_offset*/
            Dwarf_Half cuType; /*header_cu_type*/
            Dwarf_Error error;    /*error*/
            int res = DW_DLV_ERROR;
            
            struct SrcFilesData sf;
            sf.srcfilesres = DW_DLV_ERROR;
            sf.srcfiles = 0;
            sf.srcfilescount = 0;
            memset(&signature,0, sizeof(signature));
            
            //True means look in debug_Info;false use debug_types
            res = dwarf_next_cu_header_d(dbg,TRUE,&headerLength,&versionStamp,&abbrevOffset,&addressSize,&lengthSize,&extensionSize,&signature,&typeoffset,&nextHeaderOff,&cuType,&error);
            if (res == DW_DLV_NO_ENTRY) {
                break;
            }
            Dwarf_Die noDie = 0;
            Dwarf_Die cuDie = 0;
            res = dwarf_siblingof_b(dbg,noDie,TRUE,&cuDie,&error);
            [self getDieAndSiblings:dbg die:cuDie];
            resetSrcfiles(dbg,&sf);
            dwarf_dealloc_die(noDie);
            dwarf_dealloc_die(cuDie);
//            dwarf_dealloc(dbg,cuDie,DW_DLA_DIE);
//            dwarf_dealloc(dbg,noDie,DW_DLA_DIE);
        }
    }
}
static NSMutableArray *lineInfos;

+ (void)writeSymbols:(NSArray*)array{
    NSLog(@"writing file...");
    //对行信息进行排序
    [lineInfos sortUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        SymbolInfo *number1 = (SymbolInfo *)obj1;
        SymbolInfo *number2 = (SymbolInfo *)obj2;
        
        if (number1.begin  > number2.begin) {
            return NSOrderedDescending;
        }else{
            return NSOrderedAscending;
        }
    }];
    
    int lineCount = 0;
    for (int i = 0 ; i < array.count; i ++) {
        @autoreleasepool {
            NSString *all = @"";
            WBBladesSymbolRangeArtillery *symInfo = (WBBladesSymbolRangeArtillery *)array[i];
            if (symInfo.begin == symInfo.end) {
                continue;
            }
            BOOL hasLineInfo = NO;
            for (; lineCount<lineInfos.count; ) {
                SymbolInfo* lineInfo = (SymbolInfo*)lineInfos[lineCount];
                UInt64 begin = lineInfo.begin;
                UInt64 end = begin;
                if (lineCount != lineInfos.count - 1) {
                    SymbolInfo* lastLineInfo = (SymbolInfo*)lineInfos[lineCount+1];
                    end = MIN(lastLineInfo.begin,symInfo.end);
                }else{
                    end = symInfo.end;
                }
                //关键点：如果某一行代码的起始指令地址在函数符号的指令区间内，那么这一行就是这个函数的某一行
                if (lineInfo.begin >= symInfo.begin && lineInfo.begin < symInfo.end && end > begin) {
                    hasLineInfo = YES;
                    NSString *symbolLine = [NSString stringWithFormat:@"%llx\t%llx\t%@\t%@ %llu\n",begin - LOADADDR ,end - LOADADDR,symInfo.symbol,lineInfo.file,lineInfo.linenum];
                    all = [all stringByAppendingString:symbolLine];
                }else if(lineInfo.begin >= symInfo.end){
                    break;
                }
                lineCount++;
            }
            if (hasLineInfo == NO) {
                all = [NSString stringWithFormat:@"%llx\t%llx\t%@\n",symInfo.begin - LOADADDR,symInfo.end - LOADADDR,symInfo.symbol];
            }
            writefile(all,outPath);
        }
    }
    array = nil;
    [lineInfos removeAllObjects];
    writefile(@"-the end-",outPath);
}

+ (void)getDieAndSiblings:(Dwarf_Debug)dbg die:(Dwarf_Die)inDie {
    int res = DW_DLV_ERROR;
    Dwarf_Die curDie = inDie;
    Dwarf_Die child = 0;
    Dwarf_Error error = 0;
    
    [self readDieData:dbg die:curDie];
    
    for(;;) {
        Dwarf_Die sibDie = 0;
        res = dwarf_child(curDie,&child,&error);
        if (res == DW_DLV_OK) {
            [self getDieAndSiblings:dbg die:child];
            dwarf_dealloc(dbg, child, DW_DLA_DIE);
            child = 0;
        }
        res = dwarf_siblingof_b(dbg,curDie,TRUE,&sibDie,&error);
        if(res == DW_DLV_NO_ENTRY) {
            /* Done at this level. */
            break;
        }
        if(curDie != inDie) {
            dwarf_dealloc(dbg,curDie,DW_DLA_DIE);
            curDie = 0;
        }
        curDie = sibDie;
        [self readDieData:dbg die:curDie];
    }
    dwarf_dealloc(dbg,curDie,DW_DLA_DIE);
    dwarf_dealloc(dbg,error,DW_DLA_ERROR);
}


+ (void)readDieData:(Dwarf_Debug)dbg die:(Dwarf_Die)die{
    Dwarf_Half tag = 0;
    Dwarf_Error error = 0;
    int res = 0;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lineInfos = [NSMutableArray array];
    });
    res = dwarf_tag(die,&tag,&error);
    if (tag == DW_TAG_compile_unit){
        
        Dwarf_Error error = 0;
        Dwarf_Unsigned versionCount = 0;
        Dwarf_Signed lineCount = 0;
        Dwarf_Line_Context lineContext;
        Dwarf_Small dw_table_count = 0;
        Dwarf_Line *lines = NULL;
        int res = dwarf_srclines_b(die,&versionCount, &dw_table_count,  &lineContext, &error);
        res = dwarf_srclines_from_linecontext(lineContext, &lines, &lineCount, &error);
        
        for (int i = 0 ; i < lineCount; i++) {
            Dwarf_Line line = lines[i];
//            lines[i];
            char *filepath = 0;
            Dwarf_Addr address = 0;
            Dwarf_Unsigned lineno = 0;
            res = dwarf_linesrc(line, &filepath, &error);
            res = dwarf_lineno(line, &lineno, &error);
            res = dwarf_lineaddr(line, &address, &error);
            SymbolInfo *info = [SymbolInfo new];
            info.begin = address;
            info.linenum = lineno;
            info.symbol = @"";
            
            char *filename = filepath;
            filename = strrchr(filepath,'/');
            info.file = [NSString stringWithFormat:@"%s",filename];
            dwarf_dealloc(dbg,filepath, DW_DLA_STRING);
            [lineInfos addObject:info];
        }
        dwarf_srclines_dealloc_b(lineContext);
//        dwarf_srclines_dealloc(dbg, lines,symbolsCount);
        
    }
//    else if (tag == DW_TAG_subprogram){
//        [self readSubprog:dbg die:die];
//    }
    dwarf_dealloc(dbg,error,DW_DLA_ERROR);
}

//+ (void)readSubprog:(Dwarf_Debug)dbg die:(Dwarf_Die)die{
//    int res;
//    Dwarf_Error error = 0;
//    Dwarf_Attribute *attrbuf = 0;
//    Dwarf_Signed attrcount = 0;
//    Dwarf_Addr low = 0;
//    Dwarf_Addr size = 0;
//
//    char *funcname = 0;
//
//    res = dwarf_attrlist(die,&attrbuf,&attrcount,&error);
//    if(res != DW_DLV_OK) {
//        return;
//    }
//    for(int i = 0; i < attrcount ; ++i) {
//        Dwarf_Half aform;
//        res = dwarf_whatattr(attrbuf[i],&aform,&error);
//        if(res == DW_DLV_OK) {
//
//            if (aform == DW_AT_name) {
//                getString(dbg,attrbuf[i],&funcname);
//            }
//            if (aform == DW_AT_low_pc) {
//                getAddr(attrbuf[i], &low);
//            }
//
//            if (aform == DW_AT_high_pc) {
//                getAddr(attrbuf[i], &size);
//            }
//        }
//        dwarf_dealloc(dbg,attrbuf[i],DW_DLA_ATTR);
//    }
//    dwarf_dealloc(dbg,attrbuf,DW_DLA_LIST);
//    dwarf_dealloc(dbg,error,DW_DLA_ERROR);
//
//}


+ (WBBladesSymTabCommandArtillery *)symbolTabOffsetWithMachO:(NSData *)fileData {
    
    WBBladesSymTabCommandArtillery *symTabCommand = objc_getAssociatedObject(fileData, "sym");
    if (symTabCommand) {
        return symTabCommand;
    }
    //mach-o header
    mach_header_64 mhHeader;
    NSRange tmpRange = NSMakeRange(0, sizeof(mach_header_64));
    [fileData getBytes:&mhHeader range:tmpRange];
    
    //load command
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    
    //enumerate load command
    for (int i = 0; i < mhHeader.ncmds; i++) {
        
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_SYMTAB) {//find string table
            
            //get the tail of the current mach-o based on the tail of the string
            symtab_command symtab;
            [fileData getBytes:&symtab range:NSMakeRange(currentLcLocation, sizeof(symtab_command))];
            //
            WBBladesSymTabCommandArtillery *symtabModel = [[WBBladesSymTabCommandArtillery alloc] init];
            symtabModel.cmd = symtab.cmd;
            symtabModel.cmdsize = symtab.cmdsize;
            symtabModel.symbolOff = symtab.symoff;
            symtabModel.strOff = symtab.stroff;
            symtabModel.strSize = symtab.strsize;
            symtabModel.symbolNum = symtab.nsyms;
            objc_setAssociatedObject(fileData, "sym", symtabModel, OBJC_ASSOCIATION_RETAIN);
            free(cmd);
            return symtabModel;
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    return nil;
}

+ (NSArray *)getSortedSymbolList:(NSData *)fileData{
    WBBladesSymTabCommandArtillery *symCmd = [self symbolTabOffsetWithMachO:fileData];
    ptrdiff_t symbolOffset = symCmd.symbolOff;
    NSMutableDictionary *dic = @{}.mutableCopy;
    for (int i=0; i < symCmd.symbolNum ; i++) {
        @autoreleasepool {
            struct nlist_64 nlist;
            ptrdiff_t off = symbolOffset + i * sizeof(struct nlist_64);
            char *p = (char *)fileData.bytes;
            p = p + off;
            memcpy(&nlist, p, sizeof(struct nlist_64));
            {
                char buffer[201];
                ptrdiff_t off = symCmd.strOff+nlist.n_un.n_strx;
                char * p = (char *)fileData.bytes;
                p = p+off;
                memcpy(&buffer, p, 200);
                NSString *symbol = [NSString stringWithFormat:@"%s",buffer];
                unsigned long long addr = nlist.n_value;
                [dic setObject:symbol forKey:@(addr)];
            }
        }
    }
    NSArray *sortedAddr = [dic.allKeys sortedArrayUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        NSNumber *number1 = (NSNumber *)obj1;
        NSNumber *number2 = (NSNumber *)obj2;
        
        if ([number1 unsignedLongLongValue] > [number2 unsignedLongLongValue]) {
            return NSOrderedDescending;
        }else{
            return NSOrderedAscending;
        }
    }];
    NSMutableArray *allSymbols = [NSMutableArray array];
    [sortedAddr enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        
        @autoreleasepool {
            WBBladesSymbolRangeArtillery *symRanObj = [WBBladesSymbolRangeArtillery new];
            unsigned long long begin = [obj unsignedLongLongValue];
            if (begin > 0) {
                symRanObj.symbol = [dic objectForKey:obj];
                symRanObj.begin = begin;
                if (idx < sortedAddr.count - 1) {
                    symRanObj.end = [sortedAddr[idx + 1] unsignedLongLongValue];
                }else{
                    
                    //如果是最后一个
                    mach_header_64 mhHeader;
                    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
                    
                    unsigned long long currentLcLocation = sizeof(mach_header_64);
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
                                if (begin >= sectionHeader.addr && begin <= sectionHeader.addr + sectionHeader.size) {
                                    symRanObj.end = sectionHeader.addr + sectionHeader.size;
                                }
                                currentSecLocation += sizeof(section_64);
                            }
                        }
                        currentLcLocation += cmd->cmdsize;
                        free(cmd);
                    }
                }
                [allSymbols addObject:symRanObj];
            }
        }
    }];
    return allSymbols.copy;
}

@end


