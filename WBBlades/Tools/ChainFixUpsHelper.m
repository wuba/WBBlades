//
//  ChainFixUpsHelper.m
//  WBBlades
//
//  Created by wbblades on 2022/8/4.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "ChainFixUpsHelper.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>

struct dyld_chained_fixups_header
{
    uint32_t    fixups_version;    // 0
    uint32_t    starts_offset;     // offset of dyld_chained_starts_in_image in chain_data
    uint32_t    imports_offset;    // offset of imports table in chain_data
    uint32_t    symbols_offset;    // offset of symbol strings in chain_data
    uint32_t    imports_count;     // number of imported symbol names
    uint32_t    imports_format;    // DYLD_CHAINED_IMPORT*
    uint32_t    symbols_format;    // 0 => uncompressed, 1 => zlib compressed
};

enum {
    DYLD_CHAINED_IMPORT          = 1,
    DYLD_CHAINED_IMPORT_ADDEND   = 2,
    DYLD_CHAINED_IMPORT_ADDEND64 = 3,
};

// DYLD_CHAINED_IMPORT
struct dyld_chained_import
{
    uint32_t    lib_ordinal :  8,
                weak_import :  1,
                name_offset : 23;
};

// DYLD_CHAINED_IMPORT_ADDEND
struct dyld_chained_import_addend
{
    uint32_t    lib_ordinal :  8,
                weak_import :  1,
                name_offset : 23;
    int32_t     addend;
};

// DYLD_CHAINED_IMPORT_ADDEND64
struct dyld_chained_import_addend64
{
    uint64_t    lib_ordinal : 16,
                weak_import :  1,
                reserved    : 15,
                name_offset : 32;
    uint64_t    addend;
};


struct dyld_chained_ptr_64_bind {
   uint64_t     ordinal:24,
                     addend:8,
                     reserved:19,
                     next:12,
                     bind:1;
};

struct dyld_chained_ptr_generic64 {
   uint64_t     ordinal:51,
                     next:12,
                     bind:1;
};

struct dyld_chained_ptr_64_rebase
{
    uint64_t    target    : 36,    // 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset)
                high8     :  8,    // top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added, DYLD_CHAINED_PTR_64_OFFSET => before slide added)
                reserved  :  7,    // all zeros
                next      : 12,    // 4-byte stride
                bind      :  1;    // == 0
};

struct dyld_chained_starts_in_image
{
    uint32_t    seg_count;
    uint32_t    seg_info_offset[1];  // each entry is offset into this struct for that segment
    // followed by pool of dyld_chain_starts_in_segment data
};

struct dyld_chained_starts_in_segment
{
    uint32_t    size;               // size of this (amount kernel needs to copy)
    uint16_t    page_size;          // 0x1000 or 0x4000
    uint16_t    pointer_format;     // DYLD_CHAINED_PTR_*
    uint64_t    segment_offset;     // offset in memory to start of segment
    uint32_t    max_valid_pointer;  // for 32-bit OS, any value beyond this is not a pointer
    uint16_t    page_count;         // how many pages are in array
    uint16_t    page_start[1];      // each entry is offset in each page of first element in chain
                                    // or DYLD_CHAINED_PTR_START_NONE if no fixups on page
 // uint16_t    chain_starts[1];    // some 32-bit formats may require multiple starts per page.
                                    // for those, if high bit is set in page_starts[], then it
                                    // is index into chain_starts[] which is a list of starts
                                    // the last of which has the high bit set
};

// values for dyld_chained_starts_in_segment.pointer_format
enum {
    DYLD_CHAINED_PTR_ARM64E                 =  1,    // stride 8, unauth target is vmaddr
    DYLD_CHAINED_PTR_64                     =  2,    // target is vmaddr
    DYLD_CHAINED_PTR_32                     =  3,
    DYLD_CHAINED_PTR_32_CACHE               =  4,
    DYLD_CHAINED_PTR_32_FIRMWARE            =  5,
    DYLD_CHAINED_PTR_64_OFFSET              =  6,    // target is vm offset
    DYLD_CHAINED_PTR_ARM64E_OFFSET          =  7,    // old name
    DYLD_CHAINED_PTR_ARM64E_KERNEL          =  7,    // stride 4, unauth target is vm offset
    DYLD_CHAINED_PTR_64_KERNEL_CACHE        =  8,
    DYLD_CHAINED_PTR_ARM64E_USERLAND        =  9,    // stride 8, unauth target is vm offset
    DYLD_CHAINED_PTR_ARM64E_FIRMWARE        = 10,    // stride 4, unauth target is vmaddr
    DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE    = 11,    // stride 1, x86_64 kernel caches
    DYLD_CHAINED_PTR_ARM64E_USERLAND24      = 12,    // stride 8, unauth target is vm offset, 24-bit bind
};

enum {
    DYLD_CHAINED_PTR_START_NONE   = 0xFFFF, // used in page_start[] to denote a page with no fixups
    DYLD_CHAINED_PTR_START_MULTI  = 0x8000, // used in page_start[] to denote a page which has multiple starts
    DYLD_CHAINED_PTR_START_LAST   = 0x8000, // used in chain_starts[] to denote last start in list for page
};

@interface ChainFixUpsHelper()
@property (nonatomic, strong)NSData *fileData;
@end

@implementation ChainFixUpsHelper

static ChainFixUpsHelper *shareInstance = nil;

//static int areEqual(const char* a, const char* b) {
//    while (*a && *b) {
//        if (*a != *b)
//            return 0;
//        ++a;
//        ++b;
//    }
//    return *a == *b;
//}

+(ChainFixUpsHelper *)shareInstance{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shareInstance = [[self alloc] init];
    });
    return shareInstance;
}

-(NSMutableArray<NSString *> *)dylibNames{
    if(!_dylibNames){
        _dylibNames = [NSMutableArray array];
    }
    return _dylibNames;
}

-(NSMutableArray<WBChainFixupImportSymbol *> *)importSymbolPool{
    if(!_importSymbolPool){
        _importSymbolPool = [NSMutableArray array];
    }
    return _importSymbolPool;
}

-(NSMutableArray<NSString *> *)segmentNames{
    if(!_segmentNames){
        _segmentNames = [NSMutableArray array];
    }
    return _segmentNames;
}

-(NSMutableDictionary<NSString *,WBSectionRangeModel *> *)sectionRangeMap{
    if(!_sectionRangeMap){
        _sectionRangeMap = [NSMutableDictionary dictionary];
    }
    return _sectionRangeMap;
}

- (NSMutableDictionary <NSNumber *, WBChainFixupImportSymbol *> *)bindAdreesInfos {
    if (!_bindAdreesInfos) {
        _bindAdreesInfos = [@{} mutableCopy];
    }
    return _bindAdreesInfos;
}

-(instancetype)fileLoaderWithFileData:(NSData *)fileData{
    self.fileData = fileData;
    struct mach_header_64 mheader;
    [fileData getBytes:&mheader range:NSMakeRange(0, sizeof(struct mach_header_64))];
        
    uint64_t textVMAddr     = 0;
    struct linkedit_data_command chainedFixups;
    uint64_t linkeditVMAddr     = 0;
    uint64_t linkeditFileOffset = 0;
    
    NSInteger startCmd  = sizeof(mheader);
    
    for(NSInteger i = 0;i<mheader.ncmds;i++){
        struct load_command cmd;
        [self.fileData getBytes:&cmd range:NSMakeRange(startCmd, sizeof(cmd))];
        
        if (cmd.cmd == LC_DYLD_CHAINED_FIXUPS){
            self.isChainFixups = YES;
            [self.fileData getBytes:&chainedFixups range:NSMakeRange(startCmd, sizeof(chainedFixups))];
        }else if(cmd.cmd == LC_SEGMENT_64 ){
            struct segment_command_64 seg;
            [self.fileData getBytes:&seg range:NSMakeRange(startCmd, sizeof(seg))];
            [self.segmentNames addObject:[NSString stringWithFormat:@"%s",seg.segname]];
            if(strcmp(seg.segname, "__TEXT")){
                textVMAddr = seg.vmaddr;
            }
            else if ( strcmp(seg.segname, "__LINKEDIT") ) {
                linkeditVMAddr = seg.vmaddr;
                linkeditFileOffset = seg.fileoff;
            }
            //访问每个segment段的所有section的名称和区间
            for(NSInteger j = 0; j<seg.nsects;j++){
                struct section_64 section;
                [self.fileData getBytes:&section range:NSMakeRange(startCmd+sizeof(seg)+sizeof(section)*j, sizeof(struct section_64))];
                NSString *secName = [[NSString alloc] initWithUTF8String:section.sectname];
                WBSectionRangeModel *model = [[WBSectionRangeModel alloc]init];
                model.startRange = section.offset;
                model.endRange = section.offset + section.size;
                [self.sectionRangeMap setObject:model forKey:secName];
            }
        }else if (cmd.cmd == LC_LOAD_DYLIB || cmd.cmd == LC_LOAD_WEAK_DYLIB || LC_LOAD_UPWARD_DYLIB == cmd.cmd || LC_LOAD_DYLINKER == cmd.cmd) {
            //记录外部依赖的动态库
            struct dylib_command dylibs;
            [self.fileData getBytes:&dylibs range:NSMakeRange(startCmd, sizeof(dylibs))];
            uint8_t *dylid_name = (uint8_t *)malloc(150);
            [fileData getBytes:dylid_name range:NSMakeRange(startCmd +dylibs.dylib.name.offset, 150)];
            NSString *dylid_name_string = [NSString stringWithFormat:@"%s",dylid_name];
            [self.dylibNames addObject:dylid_name_string];
        }
        startCmd += cmd.cmdsize;
    }
    if(!(chainedFixups.datasize>0)){
        return self;
    }

    if (!self.isChainFixups) {
        return self;
    }
    linkeditFileOffset = chainedFixups.dataoff -  linkeditFileOffset;
    struct dyld_chained_fixups_header fixupsHeader;
    
    [self.fileData getBytes:&fixupsHeader range:NSMakeRange(linkeditFileOffset, sizeof(fixupsHeader))];
    
//    NSLog(@"dyld_chained_fixups_header 的信息如下| fixups_version | %d | starts_offset | %d | imports_offset | %d | symbols_offset | %d | imports_count | %d | imports_format | %d | symbols_format | %d |",fixupsHeader.fixups_version,fixupsHeader.starts_offset,fixupsHeader.imports_offset,fixupsHeader.symbols_offset,fixupsHeader.imports_count,fixupsHeader.imports_format,fixupsHeader.symbols_format);
    

    //输出外部导入符号
    for(NSInteger i = 0;i<fixupsHeader.imports_count;i++){
        //读取 dyld_chained_import 信息(eg: )
        NSInteger nameOffset = 0;
        NSInteger lib_index = 0;
        if (fixupsHeader.imports_format == DYLD_CHAINED_IMPORT){
            struct dyld_chained_import chained_import;
            [self.fileData getBytes:&chained_import range:NSMakeRange(linkeditFileOffset+fixupsHeader.imports_offset+sizeof(chained_import)*i, sizeof(chained_import))];
            nameOffset = chained_import.name_offset;
            uint8_t libVal = chained_import.lib_ordinal;
            int libOrdinal;
            if ( libVal > 0xF0 )
                libOrdinal = (int8_t)libVal;
            else
                libOrdinal = libVal;
            lib_index = libOrdinal;
        }else if (fixupsHeader.imports_format == DYLD_CHAINED_IMPORT_ADDEND64){
            struct dyld_chained_import_addend64 chained_import_append64;
            [self.fileData getBytes:&chained_import_append64 range:NSMakeRange(linkeditFileOffset+fixupsHeader.imports_offset+sizeof(chained_import_append64)*i, sizeof(chained_import_append64))];
            nameOffset = chained_import_append64.name_offset;
            uint8_t libVal = chained_import_append64.lib_ordinal;
            int libOrdinal;
            if ( libVal > 0xF0 )
                libOrdinal = (int8_t)libVal;
            else
                libOrdinal = libVal;
            lib_index = libOrdinal;
        }else if (fixupsHeader.imports_format == DYLD_CHAINED_IMPORT_ADDEND){
            struct dyld_chained_import_addend chained_import_append;
            [self.fileData getBytes:&chained_import_append range:NSMakeRange(linkeditFileOffset+fixupsHeader.imports_offset+sizeof(chained_import_append)*i, sizeof(chained_import_append))];
            nameOffset = chained_import_append.name_offset;
            uint8_t libVal = chained_import_append.lib_ordinal;
            int libOrdinal;
            if ( libVal > 0xF0 )
                libOrdinal = (int8_t)libVal;
            else
                libOrdinal = libVal;
            lib_index = libOrdinal;
        }
        //读取外部使用的symbolPool 的字符串
        char *symbolName = (char *)[fileData bytes] + linkeditFileOffset+fixupsHeader.symbols_offset+nameOffset;
        if (lib_index<=self.dylibNames.count && lib_index > 0){
            WBChainFixupImportSymbol *importSymbol = [[WBChainFixupImportSymbol alloc]init];
            importSymbol.dylibName = self.dylibNames[lib_index-1];
            importSymbol.importSymbolName =  @(symbolName);
            [self.importSymbolPool addObject:importSymbol];
        }else{
            WBChainFixupImportSymbol *importSymbol = [[WBChainFixupImportSymbol alloc]init];
            importSymbol.dylibName = @"/UIKit";
            importSymbol.importSymbolName =  @(symbolName);
            [self.importSymbolPool addObject:importSymbol];
        }
    }

    
    //读取 dyld_chained_starts_in_image信息
    
    struct dyld_chained_starts_in_image chained_start_image;
    [self.fileData getBytes:&chained_start_image range:NSMakeRange(linkeditFileOffset+fixupsHeader.starts_offset, sizeof(uint32_t))];
    for(NSInteger i = 0; i < chained_start_image.seg_count; i++){
        uint32_t seg_ingo_offset ;
        [self.fileData getBytes:&seg_ingo_offset range:NSMakeRange(linkeditFileOffset+fixupsHeader.starts_offset+sizeof(uint32_t)+sizeof(uint32_t) * i, sizeof(uint32_t))];
        if(seg_ingo_offset != 0){
            struct dyld_chained_starts_in_segment chained_start_segment;
            [self.fileData getBytes:&chained_start_segment range:NSMakeRange(linkeditFileOffset+fixupsHeader.starts_offset+seg_ingo_offset, sizeof(chained_start_segment))];
            NSLog(@"当前正在解析的segment[%ld]：%@ | seg_ingo_offset:%d\n          size: %d \n          pageSize: 0x%x \n          pointer_format: %d \n          segment_offset: 0x%llx \n          page_count: %d \n          page_start: 0x%x",(long)i,self.segmentNames[i],seg_ingo_offset,chained_start_segment.size,chained_start_segment.page_size,chained_start_segment.pointer_format,chained_start_segment.segment_offset,chained_start_segment.page_count,chained_start_segment.page_start[0]);
            //解析当pagecount大于1时候，每个page的偏移page_start 解析每个page中的rebase 和 bind 信息
            uint16_t    page_start[chained_start_segment.page_count];
            [self.fileData getBytes:&page_start range:NSMakeRange(linkeditFileOffset+fixupsHeader.starts_offset+seg_ingo_offset+sizeof(chained_start_segment)-sizeof(uint16_t), sizeof(uint16_t)*chained_start_segment.page_count)];
            for(NSInteger i = 0; i<chained_start_segment.page_count;i++){
                switch (chained_start_segment.pointer_format) {
                    case DYLD_CHAINED_PTR_64_OFFSET:
                    case DYLD_CHAINED_PTR_64:
                        //此时使用dyld_chained_ptr_64_bind或者dyld_chained_ptr_64_rebase去解析均可，我们通过判断bind位是否==1来判定 找到链表头结点
                    {
                        NSInteger pageStart = chained_start_segment.segment_offset+page_start[i]+i*chained_start_segment.page_size;
//                        NSLog(@"=====================pageNumber：%ld======================================",(long)i);
                        [self walkChainFixUpsWithOffset:pageStart];
                    }
                        break;
                    default:
                        NSLog(@"请检查Mach-O的架构");
                        break;
                }
            }
        }
    }
    return self;
}

-(void)walkChainFixUpsWithOffset:(NSInteger)offset{
    struct dyld_chained_ptr_generic64  generic64;
    NSInteger chained_next_offset = offset;
    do {
        uint64_t rawValue;
        [self.fileData getBytes:&rawValue range:NSMakeRange(chained_next_offset, sizeof(rawValue))];
        [self.fileData getBytes:&generic64 range:NSMakeRange(chained_next_offset, sizeof(generic64))];
        if(generic64.bind == 1){
            struct dyld_chained_ptr_64_bind  generic64Bind;
            [self.fileData getBytes:&generic64Bind range:NSMakeRange(chained_next_offset, sizeof(generic64Bind))];
            self.bindAdreesInfos[@(chained_next_offset)] = self.importSymbolPool[generic64Bind.ordinal];
            NSLog(@"0x%lx  raw:0x%llx bind：(next：%d, ordinal：%d, append：%d, symbol：%@)",(long)chained_next_offset,rawValue,generic64Bind.next,generic64Bind.ordinal,generic64Bind.addend,self.importSymbolPool[generic64Bind.ordinal]);
        }else{
            struct dyld_chained_ptr_64_rebase  generic64Rebase;
            [self.fileData getBytes:&generic64Rebase range:NSMakeRange(chained_next_offset, sizeof(generic64Rebase))];
            NSLog(@"0x%lx  raw:0x%llx  rebase：(next：%d, target：0x%llx, heigh8：0x%x)",(long)chained_next_offset,rawValue,generic64Rebase.next,generic64Rebase.target,generic64Rebase.high8);
        }
        chained_next_offset += generic64.next * 4;
    } while (generic64.next != 0);
}


-(BOOL)validateSectionWithFileoffset:(long long )offset sectionName:(NSString *)name{
    if(!name || offset<=0){
        return NO;
    }
    WBSectionRangeModel *targetModel = self.sectionRangeMap[name];
    if(targetModel && offset<=targetModel.endRange && offset>= targetModel.startRange){
        return YES;
    }
    return NO;
}

@end


@implementation WBSectionRangeModel


@end

@implementation WBChainFixupImportSymbol


@end


