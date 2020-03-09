//
//  WBBladesScanManager+UnuseClassScan.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/8/5.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager+UnuseClassScan.h"
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <objc/runtime.h>

#import "WBBladesTool.h"
#import "WBBladesObjectHeader.h"
#import "WBBladesDefines.h"
#import "capstone.h"


@implementation WBBladesScanManager (UnuseClassScan)

static cs_insn *s_cs_insn;
static section_64 textList = {0};

//dump binary file's classes
+ (NSSet *)dumpClassList:(NSData *)fileData {
    
    if (!fileData || ![self isSupport:fileData]) {
        return nil;
    }
    
    NSMutableSet *set = [NSMutableSet set];
    
    NSRange range = NSMakeRange(8, 0);
    WBBladesObjectHeader * symtabHeader = [self scanSymtabHeader:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(symtabHeader.range), 0);
    WBBladesSymTab * symTab = [self scanSymbolTab:fileData range:range];
    
    range = NSMakeRange(NSMaxRange(symTab.range), 0);
    WBBladesStringTab * stringTab = [self scanStringTab:fileData range:range];
    
    for (NSString *symbol in stringTab.strings) {
        
        if ([symbol hasPrefix:CLASS_SYMBOL_PRE] ||
            [symbol hasPrefix:METACLASS_SYMBOL_PRE]) {
            NSString * className = [symbol stringByReplacingOccurrencesOfString:CLASS_SYMBOL_PRE withString:@""];
            className = [className stringByReplacingOccurrencesOfString:METACLASS_SYMBOL_PRE withString:@""];
            [set addObject:className];
        }
    }
    return [set copy];
}

#pragma mark Scan
//scan specified file to find unused classes
+ (NSSet *)scanAllClassWithFileData:(NSData*)fileData classes:(NSSet *)aimClasses {
    
    NSLog(@"目标%ld个类",aimClasses.count);
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    section_64 classList = {0};
    section_64 classrefList= {0};
    section_64 nlclsList= {0};
    section_64 cfstringList= {0};
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command *cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];
            
            //enumerate classlist、selref、classref、nlcls、cfstring section
            if ([segName isEqualToString:SEGMENT_DATA] ||
                [segName isEqualToString:SEGMENT_DATA_CONST]) {
                //enumerate section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    
                    //note classlist
                    if ([secName isEqualToString:DATA_CLASSLIST_SECTION] ||
                        [secName isEqualToString:CONST_DATA_CLASSLIST_SECTION]) {
                        classList = sectionHeader;
                    }
                    //note classref
                    if ([secName isEqualToString:DATA_CLASSREF_SECTION] ||
                        [secName isEqualToString:CONST_DATA_CLASSREF_SECTION]) {
                        classrefList = sectionHeader;
                    }
                    //note nclasslist
                    if ([secName isEqualToString:DATA_NCLSLIST_SECTION] ||
                        [secName isEqualToString:CONST_DATA_NCLSLIST_SECTION]) {
                        nlclsList = sectionHeader;
                    }
                    //note Cstring
                    if ([secName isEqualToString:DATA_CSTRING]) {
                        cfstringList = sectionHeader;
                    }
                    currentSecLocation += sizeof(section_64);
                }
            } else if ([segName isEqualToString:SEGMENT_TEXT]) {
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    
                    if ([secName isEqualToString:TEXT_TEXT_SECTION]) {
                        textList = sectionHeader;
                        
                        //Disassemble the assembly code of the binary
                        s_cs_insn = [WBBladesTool disassemWithMachOFile:fileData from:sectionHeader.offset length:sectionHeader.size];
                    }
                    
                    currentSecLocation += sizeof(section_64);
                }
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    NSMutableSet *classrefSet = [NSMutableSet set];
    
    //read nlclslist
     [self readNLClsList:nlclsList set:classrefSet fileData:fileData];
    
    //read classref
    [self readClsRefList:classrefList aimClasses:aimClasses set:classrefSet fileData:fileData];
    
    //read cfstring
    [self readCStringList:cfstringList set:classrefSet fileData:fileData];
    
    //read classlist
    NSMutableSet *classSet = [self readClassList:classList aimClasses:aimClasses set:classrefSet fileData:fileData];
    [classrefSet enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        [classSet removeObject:obj];
    }];
    
    return classSet;
}

+ (BOOL)scanSymbolTabWithFileData:(NSData *)fileData helper:(WBBladesHelper *)helper vm:(unsigned long long )vm {
        
    //binary files's symbol table
    WBBladesSymTabCommand *symCmd = [self symbolTabOffsetWithMachO:fileData];
    unsigned long long symbolOffset = symCmd.symbolOff;
    unsigned long long targetAddress = helper.offset;
    
    if (!symCmd.withDWARF) {
        return YES;
    }
    
    //target address
    char *targetStr = (char *)[[[NSString stringWithFormat:@"#0x%llX",targetAddress] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
    
    //target high address
    char *targetHighStr =(char *) [[[NSString stringWithFormat:@"#0x%llX",targetAddress & 0xFFFFFFFFFFFFF000] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
    
    //Target low address
    char *targetLowStr = (char *)[[[NSString stringWithFormat:@"#0x%llX",targetAddress & 0x0000000000000fff] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
        
    //enumerate symbol table
    for (int i=0; i < symCmd.symbolNum - 1; i++) {
        nlist_64 nlist;
        ptrdiff_t off = symbolOffset + i * sizeof(nlist_64);
        char *p = (char *)fileData.bytes;
        p = p + off;
        memcpy(&nlist, p, sizeof(nlist_64));
        
        //https://developer.apple.com/documentation/kernel/nlist_64
        if (nlist.n_sect == 1 &&
            (nlist.n_type == 0x0e || nlist.n_type == 0x0f)) {
            
            char buffer[201];
            ptrdiff_t off = symCmd.strOff+nlist.n_un.n_strx;
            char * p = (char *)fileData.bytes;
            p = p+off;
            memcpy(&buffer, p, 200);
            char * className = strtok(buffer," ");
            className = strstr(className,"[");
            if (className) {
                className = className+1;
            } else {
                className = buffer;
            }
            if (strcmp(className,[helper.className UTF8String]) == 0) {
                continue;
            }
            
            unsigned long long begin = nlist.n_value;
            
            //set the starting point of a function instruction, start enumerating to see if a class address exists
            //if true, you can assume that this class is used in this function
            BOOL use = [self scanSELCallerWithAddress:targetStr heigh:targetHighStr low:targetLowStr begin:begin vm:vm];
            if (use) {
                return YES;
            }
        }
    }
    return NO;
}

+ (BOOL)scanSELCallerWithAddress:(char * )targetStr heigh:(char *)targetHighStr low:(char *)targetLowStr  begin:(unsigned long long)begin  vm:(unsigned long long )vm {
    char *asmStr;
    BOOL high = NO;
    if (begin < (textList.offset + vm)) {
        return NO;
    }
    //enumerate function instruction
    do {
        unsigned long long index = (begin - textList.offset - vm) / 4;
        char *dataStr = s_cs_insn[index].op_str;
        asmStr = s_cs_insn[index].mnemonic;
        if (strcmp(".byte",asmStr) == 0) {
            return NO;
        }
        if (strstr(dataStr, targetStr)) {//hit
            return YES;
        } else if (strstr(dataStr, targetHighStr)) {//hit high address
            high = YES;
        } else if (strstr(dataStr, targetLowStr)) {//after hit high address,hit low address
            if (high) {
                return  YES;
            }
        }
        begin += 4;
    } while (strcmp("ret",asmStr) != 0 );//result
    return NO;
    
}

#pragma mark Read
+ (NSMutableSet *)readClassList:(section_64)classList aimClasses:(NSSet *)aimClasses set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSMutableSet *classSet = [NSMutableSet set];
    unsigned long long vm = classList.addr - classList.offset;
    unsigned long long max = [fileData length];
    NSRange  range = NSMakeRange(classList.offset, 0);
        for (int i = 0; i < classList.size / 8 ; i++) {
            @autoreleasepool {
                
                unsigned long long classAddress;
                NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
                [data getBytes:&classAddress range:NSMakeRange(0, 8)];
                unsigned long long classOffset = classAddress - vm;
                
                //class struct
                class64 targetClass = {0};
                NSRange targetClassRange = NSMakeRange(classOffset, 0);
                data = [WBBladesTool readBytes:targetClassRange length:sizeof(class64) fromFile:fileData];
                [data getBytes:&targetClass length:sizeof(class64)];
                
                //class info struct
                class64Info targetClassInfo = {0};
                unsigned long long targetClassInfoOffset = targetClass.data - vm;
                targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                
                unsigned long long classNameOffset = targetClassInfo.name - vm;
                
                //superclass info
                if (targetClass.superClass != 0) {
                    class64 superClass = {0};
                    NSRange superClassRange = NSMakeRange(targetClass.superClass - vm, 0);
                    data = [WBBladesTool readBytes:superClassRange length:sizeof(class64) fromFile:fileData];
                    [data getBytes:&superClass length:sizeof(class64)];
                    
                    class64Info superClassInfo = {0};
                    unsigned long long superClassInfoOffset = superClass.data - vm;
                    superClassInfoOffset = (superClassInfoOffset / 8) * 8;
                    NSRange superClassInfoRange = NSMakeRange(superClassInfoOffset, 0);
                    data = [WBBladesTool readBytes:superClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                    [data getBytes:&superClassInfo length:sizeof(class64Info)];
                    unsigned long long superClassNameOffset = superClassInfo.name - vm;
                    
                    //class name 50 bytes maximum
                    uint8_t * buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                    [fileData getBytes:buffer range:NSMakeRange(superClassNameOffset, CLASSNAME_MAX_LEN)];
                    NSString * superClassName = NSSTRING(buffer);
                    free(buffer);
                    if (superClassName) {
                        [classrefSet addObject:superClassName];
                    }
                }
                
                //class name 50 bytes maximum
                uint8_t * buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                NSString * className = NSSTRING(buffer);
                free(buffer);
                
                //judge Whether the current class is in the target class collection
                if ([aimClasses count]>0 && ![aimClasses containsObject:className]) {
                    continue;
                }
                [classSet addObject:className];
                
                //enumerate member variables
                unsigned long long varListOffset = targetClassInfo.instanceVariables - vm;
                if (varListOffset > 0 && varListOffset < max) {
                    unsigned int varCount;
                    NSRange varRange = NSMakeRange(varListOffset + 4, 0);
                    data = [WBBladesTool readBytes:varRange length:4 fromFile:fileData];
                    [data getBytes:&varCount length:4];
                    for (int j = 0; j<varCount; j++) {
                        NSRange varRange = NSMakeRange(varListOffset+sizeof(ivar64_list_t) + sizeof(ivar64_t) * j, sizeof(ivar64_t));
                        ivar64_t var = {};
                        [fileData getBytes:&var range:varRange];
                        unsigned long long methodNameOffset = var.type;
                        methodNameOffset = methodNameOffset - vm;
                        uint8_t * buffer = (uint8_t *)malloc(METHODNAME_MAX_LEN + 1); buffer[METHODNAME_MAX_LEN] = '\0';
                        if (methodNameOffset > 0 && methodNameOffset < max) {
                            [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,METHODNAME_MAX_LEN)];
                            NSString *typeName = NSSTRING(buffer);
                            if (typeName) {
                                typeName = [typeName stringByReplacingOccurrencesOfString:@"@\"" withString:@""];
                                typeName = [typeName stringByReplacingOccurrencesOfString:@"\"" withString:@""];
                                [classrefSet addObject:typeName];
                            }
                        }
                    }
                }
            }
        }
    return classSet;
}

+ (void)readCStringList:(section_64)cfstringList set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(cfstringList.offset, 0);
    unsigned long long vm = cfstringList.addr - cfstringList.offset;
    unsigned long long max = [fileData length];
    for (int i = 0; i < cfstringList.size / sizeof(cfstring64); i++) {
         @autoreleasepool {
             
             cfstring64 cfstring;
             NSData *data = [WBBladesTool readBytes:range length:sizeof(cfstring64) fromFile:fileData];
             [data getBytes:&cfstring range:NSMakeRange(0, sizeof(cfstring64))];
             unsigned long long stringOff = cfstring.stringAddress - vm;
             if (stringOff > 0 && stringOff < max) {
                 uint8_t *buffer = (uint8_t *)malloc(cfstring.size + 1); buffer[cfstring.size] = '\0';
                 [fileData getBytes:buffer range:NSMakeRange(stringOff, cfstring.size)];
                 NSString *className = NSSTRING(buffer);
                 free(buffer);
                 if (className){
                     [classrefSet addObject:className];
                 }
             }
         }
     }
}

+ (void)readClsRefList:(section_64)classrefList aimClasses:(NSSet *)aimClasses set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(classrefList.offset, 0);
    unsigned long long vm = classrefList.addr - classrefList.offset;
    unsigned long long max = [fileData length];
    for (int i = 0; i < classrefList.size / 8; i++) {
           @autoreleasepool {
               
               unsigned long long classAddress;
               NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
               [data getBytes:&classAddress range:NSMakeRange(0, 8)];
               classAddress = classAddress - vm;
               //method name 150 bytes maximum
               if (classAddress > 0 && classAddress < max) {
                   
                   //class64 struct
                   class64 targetClass;
                   ptrdiff_t off = classAddress;
                   char *p = (char *)fileData.bytes;
                   p = p+off;
                   memcpy(&targetClass, p, sizeof(class64));
                   
                   //class64info struct
                   class64Info targetClassInfo = {0};
                   unsigned long long targetClassInfoOffset = targetClass.data - vm;
                   targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                   NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                   data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                   [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                   unsigned long long classNameOffset = targetClassInfo.name - vm;
                   
                   //class name 50 bytes maximum
                   uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                   [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                   NSString *className = NSSTRING(buffer);
                   free(buffer);
                   
                   if (className) {
                       WBBladesHelper *helper = [WBBladesHelper new];
                       helper.className = className;
                       helper.offset = range.location;
                       if ([aimClasses count] == 0 || [aimClasses containsObject:className]) {
                           
                           //other class is calling current class
                           if ([self scanSymbolTabWithFileData:fileData helper:helper vm:vm]) {
                               [classrefSet addObject:className];
                           }
                       } else {
                           [classrefSet addObject:className];
                       }
                   }
               }
           }
       }
}

+ (void)readNLClsList:(section_64)nlclsList set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    //nlclslist
    NSRange range = NSMakeRange(nlclsList.offset, 0);
    unsigned long long vm = nlclsList.addr - nlclsList.offset;
    unsigned long long max = [fileData length];
     for (int i = 0; i < nlclsList.size / 8; i++) {
         @autoreleasepool {
           
             unsigned long long classAddress;
             NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
             [data getBytes:&classAddress range:NSMakeRange(0, 8)];
             classAddress = classAddress - vm;
             //method name 150 bytes maximum
             if (classAddress > 0 && classAddress < max) {
                 
                 class64 targetClass;
                 [fileData getBytes:&targetClass range:NSMakeRange(classAddress,sizeof(class64))];
                 
                 class64Info targetClassInfo = {0};
                 unsigned long long targetClassInfoOffset = targetClass.data - vm;
                 targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                 NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                 data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                 [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                 unsigned long long classNameOffset = targetClassInfo.name - vm;
                 
                 //class name 50 bytes maximum
                 uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                 [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                 NSString *className = NSSTRING(buffer);
                 free(buffer);
                 if (className) {
                     [classrefSet addObject:className];
                 }
             }
         }
     }
}

//
+ (WBBladesSymTabCommand *)symbolTabOffsetWithMachO:(NSData *)fileData {
    
    WBBladesSymTabCommand *symTabCommand = objc_getAssociatedObject(fileData, "sym");
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
            WBBladesSymTabCommand *symtabModel = [[WBBladesSymTabCommand alloc] init];
            symtabModel.cmd = symtab.cmd;
            symtabModel.cmdsize = symtab.cmdsize;
            symtabModel.symbolOff = symtab.symoff;
            symtabModel.strOff = symtab.stroff;
            symtabModel.strSize = symtab.strsize;
            symtabModel.symbolNum = symtab.nsyms;
            symtabModel.withDWARF = YES;
            //judge whether the file is a divested symbol table
            if (symtabModel.symbolNum > 0) {
                nlist_64 nlist;
                ptrdiff_t off = symtabModel.symbolOff;
                char * p = (char *)fileData.bytes;
                p = p+off;
                memcpy(&nlist, p, sizeof(nlist_64));
                if (nlist.n_type == SPECIAL_SECTION_TYPE && nlist.n_sect == N_UNDF && nlist.n_value == SPECIAL_NUM) {
                    symtabModel.withDWARF = NO;
                }
            }
            
            objc_setAssociatedObject(fileData, "sym", symtabModel, OBJC_ASSOCIATION_RETAIN);
            return symtabModel;
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    return nil;
}


@end
