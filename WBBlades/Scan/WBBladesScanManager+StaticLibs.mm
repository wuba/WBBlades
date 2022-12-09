//
//  WBBladesScanManager+StaticLibs.m
//  WBBlades
//
//  Created by wbblades on 2022/4/27.
//

#import "WBBladesScanManager+StaticLibs.h"
#import "WBBladesLinkManager.h"
#import "WBBladesFileManager+StaticLibs.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>

@implementation WBBladesScanManager (StaticLibs)

#pragma mark Scan
//scan static library size
+ (WBBladesStaticLibraryModel *)scanStaticLibraryModel:(NSData *)fileData {
    
    WBBladesStaticLibraryModel *staticLibraryModel = [WBBladesStaticLibraryModel new];
    staticLibraryModel.undefinedSymbols = [NSMutableSet set];
    staticLibraryModel.definedSymbols = [NSMutableSet set];

    //judge whether it is a static library
    if ([fileData length] < sizeof(mach_header) || ![self isSupport:fileData]) {
        staticLibraryModel.linkSize = 0;
        return staticLibraryModel;
    }
    NSMutableArray *objects = [NSMutableArray array];
    
    //Get the file eigenvalue
    mach_header header = *(mach_header*)((mach_header *)[fileData bytes]);
    
    if (header.filetype == MH_OBJECT) {//it is a object file
        WBBladesObject *object = [WBBladesObject new];
        NSRange range = NSMakeRange(0, 0);
        
        //create mach-O file
        WBBladesObjectMachO *macho = [WBBladesScanManager scanObjectMachO:fileData range:range];
        object.objectMachO = macho;
        [objects addObject:object];
    } else if (header.filetype == MH_DYLIB || header.filetype == MH_EXECUTE) {//it is a dynamic library or  executable file
        staticLibraryModel.linkSize = [fileData length];
        return staticLibraryModel;
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
    
    //undefine symbols
    NSMutableSet *undefinedSymbols = [NSMutableSet set];
    NSMutableSet *definedSymbols = [NSMutableSet set];

    for (WBBladesObject *object in objects) {
        for (NSString *symbol in object.objectMachO.undefinedSymbols) {
            [undefinedSymbols addObject:symbol];
        }
        for (NSString *symbol in object.objectMachO.definedSymbols) {
            [definedSymbols addObject:symbol];
        }
    }
    for (NSString *symbol in definedSymbols) {
        [undefinedSymbols removeObject:symbol];
    }
    staticLibraryModel.linkSize = linkSize;
    staticLibraryModel.definedSymbols = definedSymbols;
    staticLibraryModel.undefinedSymbols = undefinedSymbols;
    return staticLibraryModel;
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
