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
#import <mach-o/ldsyms.h>
#import <mach-o/getsect.h>
#import <objc/runtime.h>
#import "WBBladesTool.h"
#import "WBBladesObjectHeader.h"
#import "WBBladesDefines.h"
#import "capstone.h"
#import "WBBladesCMD.h"
//#import "ArtilleryModels.h"

#define ScanUnusedClassLogInfo(log) \
if (scanProgressBlock) {\
    scanProgressBlock(log);\
}

@implementation WBBladesScanManager (UnuseClassScan)

static cs_insn *s_cs_insn;
static section_64 textList = {0};
static section_64 textConst = {0};
static NSArray *symbols;

/**
 功能：无用代码检测时，可以输入静态库，然后从静态库中提取类集合。在后续的无用代码检测流程中，我们只检测这部分集合内的无用代码，其他类是否有被使用不会被检测。该方法的作用就是从指定的静态库中提取类集合。
 fileData：从磁盘中读取的二进制文件，通常是静态库文件
 */
+ (NSSet *)dumpClassList:(NSData *)fileData {
    
    if (!fileData || ![WBBladesTool isSupport:fileData]) {
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
/**
 功能：无用代码检测的主流程函数。其主流程如下：
     （1）读取nlclslist中的数据，该数据通常为实现了+laod的类，这些类我们会标记为有用类
     （2）读取nlcatlist，该数据通常为分类中实现了+load的类，这些类我们会标记为有用类
     （3）读取classref，该数据通常为被显式调用的OC类，例如+[ClassA func]，ClassA会被标记为有用类
     （4）读取cfstring，该数据通常记录被使用到的OC的字符串，例如 @”ClassA“,ClassA会被标记为有用类，这一步是为了解决runtime 动态调用类的识别问题，但是如果是字符串拼接后动态调用，那么我们依旧无法识别。
     （5）遍历swift5Types，该数据通常记录swift中的类型，例如枚举、结构体、类等等。从swift5Types中，我们会在汇编代码中，查找每个swift类的访问函数地址，如果找到则说明该类有被使用，如果没找到则说明没有被使用。
     （6）遍历classlist，该数据通常存储OC&Swift的所有类集合。在遍历类的过程中，我们会读取每个类的属性、父类，并将属性类型和父类类型加入到有用类集合中。
     （7）从符号表中泛型的参数，并将参数加入到有用类集合中。例如<MyClass>，MyClass会被检测出并加入到有用类集合中。
     （8）泛型类没有被存储到classlist中，因此需要将泛型类补充到集合中
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 aimClasses：只查找给定的类集合中的无用类。
 */
+ (NSSet *)scanAllClassWithFileData:(NSData*)fileData classes:(NSSet *)aimClasses progressBlock:(void (^)(NSString *))scanProgressBlock {
    //    [self readDwarf];
    //    return nil;
        if (aimClasses.count != 0) {
            NSLog(@"在给定的%ld个类中搜索",aimClasses.count);
        }
        mach_header_64 mhHeader;
        [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];

        if (mhHeader.filetype != MH_EXECUTE && mhHeader.filetype != MH_DYLIB) {
            NSLog(@"参数异常，-unused 参数不是可执行文件");
            ScanUnusedClassLogInfo(@"参数异常，传入的不是可执行文件");
            return nil;
        }
        section_64 classList = {0};
        section_64 classrefList= {0};
        section_64 nlclsList= {0};
        section_64 nlcatList= {0};
        section_64 cfstringList= {0};
        section_64 swift5Types = {0};

        segment_command_64 linkEdit = {0};

        unsigned long long currentLcLocation = sizeof(mach_header_64);
        for (int i = 0; i < mhHeader.ncmds; i++) {
            load_command *cmd = (load_command *)malloc(sizeof(load_command));
            [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

            if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)

                segment_command_64 segmentCommand;
                [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
                NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];

                //enumerate classlist、selref、classref、nlcls、cfstring section
                if ((segmentCommand.maxprot &( VM_PROT_WRITE | VM_PROT_READ)) == (VM_PROT_WRITE | VM_PROT_READ)) {
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
                        //note ncatlist
                        if ([secName isEqualToString:DATA_NCATLIST_SECTION] ||
                            [secName isEqualToString:CONST_DATA_NCATLIST_SECTION]) {
                            nlcatList = sectionHeader;
                        }
                        //note Cstring
                        if ([secName isEqualToString:DATA_CSTRING]) {
                            cfstringList = sectionHeader;
                        }
                        currentSecLocation += sizeof(section_64);
                    }
                } else if ((segmentCommand.maxprot &( VM_PROT_READ | VM_PROT_EXECUTE)) == (VM_PROT_READ | VM_PROT_EXECUTE)) {
                    unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                    for (int j = 0; j < segmentCommand.nsects; j++) {

                        section_64 sectionHeader;
                        [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                        NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                        if ([secName isEqualToString:TEXT_TEXT_SECTION]) {
                            textList = sectionHeader;

                            //Disassemble the assembly code of the binary
                            s_cs_insn = [WBBladesTool disassemWithMachOFile:fileData from:sectionHeader.offset length:sectionHeader.size];
                        }else if([secName isEqualToString:TEXT_SWIFT5_TYPES]){
                            swift5Types = sectionHeader;
                        }
                        currentSecLocation += sizeof(section_64);
                    }
                }else if([segName isEqualToString:SEGMENT_LINKEDIT]){
                    linkEdit = segmentCommand;
                }
            }
            currentLcLocation += cmd->cmdsize;
            free(cmd);
        }

        NSMutableSet *classrefSet = [NSMutableSet set];

        //read nlclslist
        ScanUnusedClassLogInfo(@"开始读取nlclslist section，读取包含load方法的类...");
        [self readNLClsList:nlclsList set:classrefSet fileData:fileData];
    
        //read nlcatlist
        ScanUnusedClassLogInfo(@"开始读取nlcatlist section，读取包含load方法的分类...");
        [self readNLCatList:nlcatList set:classrefSet fileData:fileData];

        //read classref
        ScanUnusedClassLogInfo(@"开始读取classref section...");
        [self readClsRefList:classrefList aimClasses:aimClasses set:classrefSet fileData:fileData];

        //read __cstring
        ScanUnusedClassLogInfo(@"开始读取__cfstring section...");
        [self readCStringList:cfstringList set:classrefSet fileData:fileData];

        //read swift5Types
        ScanUnusedClassLogInfo(@"开始读取swift5Types section...");
        ScanUnusedClassLogInfo(@"在反汇编指令中查找Swift的accessfunc...");
        NSArray *swiftGenericTypes = [self readSwiftTypes:swift5Types set:classrefSet fileData:fileData];

        //read classlist - OBJC
        ScanUnusedClassLogInfo(@"开始读取classlist section...");
        NSMutableSet *classSet = [self readClassList:classList aimClasses:aimClasses set:classrefSet fileData:fileData];
    //    73317
        //泛型参数约束
        [self readSwiftGenericRequire:classrefSet fileData:fileData];

        //泛型不在classlist里
        [classSet addObjectsFromArray:swiftGenericTypes];

        ScanUnusedClassLogInfo(@"读取完毕，开始检测无用类...");
        return [self diffClasses:classSet used:classrefSet];
    }
/**
 功能：对类做diff，差集即为无用类集合。在diff过程中，如果遇到Swift类则需要进行demangleName处理
 allClasses：所有的类
 usedClasses：被标记为有用到的类
 */
+ (NSSet*)diffClasses:(NSMutableSet *)allClasses used:(NSMutableSet *)usedClasses{
    [allClasses enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *className = (NSString *)obj;
        if ([className hasPrefix:@"_TtC"]) {
            NSString *demangleName = [WBBladesTool getDemangleName:className];
            if ([usedClasses containsObject:demangleName] && demangleName.length > 0) {
                [usedClasses addObject:className];
            }
        } else if ([className hasPrefix:@"PodsDummy_"]) {
            //过滤掉PodsDummy_开头的无效类
            [usedClasses addObject:className];
        }
    }];

    [usedClasses enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([allClasses containsObject:obj]) {
            [allClasses removeObject:obj];
        }
    }];
    NSMutableSet *result = [NSMutableSet set];
    [allClasses enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *demangleName = @"";
        if ([obj hasPrefix:@"_Tt"]) {
            demangleName = [WBBladesTool getDemangleName:obj]?:@"";
        }
        NSString *className = demangleName.length > 0 ? demangleName : obj;
        [result addObject:className];
    }];
    NSLog(@"%@",result);
    return result;
}

/**
 功能：在指定的汇编代码中查找指定的地址。此功能在机器指令反汇编后，得到汇编代码后才能使用。
 targetStr：完整的地址
 targetHighStr：在汇编代码中，很多情况下不是直接对targetStr进行使用，而是将targetStr拆分为高位和低位2部分数据，这里的targetHighStr就是高位数据
 targetLowStr：低位数据
 begin：从哪个字节开始进行查找
 end：在哪个字节结束查找
 
 */
+ (BOOL)scanSELCallerWithAddress:(char * )targetStr heigh:(char *)targetHighStr low:(char *)targetLowStr begin:(unsigned long long)begin end:(unsigned long long)end {

    char *asmStr;
    BOOL high = NO;
    if (begin < (textList.addr)) {
        return NO;
    }
    unsigned long long maxText = textList.addr + textList.size;
    end = MIN(maxText, end);
    //enumerate function instruction
    do {
        unsigned long long index = (begin - textList.addr) / 4;
        char *dataStr = s_cs_insn[index].op_str;
        asmStr = s_cs_insn[index].mnemonic;
        if (asmStr == NULL || strcmp(".byte",asmStr) == 0) {
            return NO;
        }
        if (strstr(dataStr, targetStr)) {//hit
            return YES;
        } else if (strstr(dataStr, targetHighStr) && strstr(asmStr, "adrp")) {//hit high address
            high = YES;
        } else if (strstr(dataStr, targetLowStr)) {//after hit high address,hit low address
            if (high) {
                return  YES;
            }
        }
        begin += 4;
    } while (strcmp("ret",asmStr) != 0 && (begin < end));//result
    return NO;

}


#pragma mark Read
/**
 功能：获取classlist section中的数据，并遍历每个类的父类及属性。将父类和属性纳入到有用类集合中
 classList：classlist section的section_64结构体，里面记录了classlist section的引导信息
 aimClasses：只检测指定的类，此数据从静态库中提取
 */
+ (NSMutableSet *)readClassList:(section_64)classList aimClasses:(NSSet *)aimClasses set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSMutableSet *classSet = [NSMutableSet set];
    unsigned long long max = [fileData length];
    NSRange  range = NSMakeRange(classList.offset, 0);
        for (int i = 0; i < classList.size / 8 ; i++) {
            @autoreleasepool {

                unsigned long long classAddress;
                NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
                [data getBytes:&classAddress range:NSMakeRange(0, 8)];
                unsigned long long classOffset = [WBBladesTool getOffsetFromVmAddress:classAddress fileData:fileData];

                //class struct
                class64 targetClass = {0};
                NSRange targetClassRange = NSMakeRange(classOffset, 0);
                data = [WBBladesTool readBytes:targetClassRange length:sizeof(class64) fromFile:fileData];
                [data getBytes:&targetClass length:sizeof(class64)];

                //class info struct
                class64Info targetClassInfo = {0};
                unsigned long long targetClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.data fileData:fileData];
                targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                [data getBytes:&targetClassInfo length:sizeof(class64Info)];

                unsigned long long classNameOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.name fileData:fileData];

                //superclass info
                if (targetClass.superClass != 0) {
                    class64 superClass = {0};
                    NSRange superClassRange = NSMakeRange([WBBladesTool getOffsetFromVmAddress:targetClass.superClass fileData:fileData], 0);
                    data = [WBBladesTool readBytes:superClassRange length:sizeof(class64) fromFile:fileData];
                    [data getBytes:&superClass length:sizeof(class64)];

                    class64Info superClassInfo = {0};
                    unsigned long long superClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:superClass.data fileData:fileData];
                    superClassInfoOffset = (superClassInfoOffset / 8) * 8;
                    NSRange superClassInfoRange = NSMakeRange(superClassInfoOffset, 0);
                    data = [WBBladesTool readBytes:superClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                    [data getBytes:&superClassInfo length:sizeof(class64Info)];
                    unsigned long long superClassNameOffset = [WBBladesTool getOffsetFromVmAddress:superClassInfo.name fileData:fileData];

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
                if (([aimClasses count]>0 && ![aimClasses containsObject:className])) {
                    continue;
                }

                if (className)[classSet addObject:className];

                //enumerate member variables
                unsigned long long varListOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.instanceVariables fileData:fileData];
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
                        methodNameOffset = [WBBladesTool getOffsetFromVmAddress:methodNameOffset fileData:fileData];
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

/**
 功能：该函数目的是为了获取项目中用到的所有字符串，例如 @”String“。获取到字符串后我们”勉强“把这些字符串都当做runtime动态调用的类。
 classrefSet：被引用的类的集合，string会被加入到这个集合中
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 */
+ (void)readCStringList:(section_64)cfstringList set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(cfstringList.offset, 0);
    unsigned long long max = [fileData length];
    for (int i = 0; i < cfstringList.size / sizeof(cfstring64); i++) {
         @autoreleasepool {

             cfstring64 cfstring;
             NSData *data = [WBBladesTool readBytes:range length:sizeof(cfstring64) fromFile:fileData];
             [data getBytes:&cfstring range:NSMakeRange(0, sizeof(cfstring64))];
             unsigned long long stringOff = [WBBladesTool getOffsetFromVmAddress:cfstring.stringAddress fileData:fileData];
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

/**
 功能：读取二进制文件中的classref数据，classref中存放的是被显式调用的类（不包括Swift类）。例如+[ClassA func]，ClassA会被存放到classref中。
 aimClasses：只检测指定的类，此数据从静态库中提取
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 */
+ (void)readClsRefList:(section_64)classrefList aimClasses:(NSSet *)aimClasses set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(classrefList.offset, 0);
    unsigned long long max = [fileData length];
    for (int i = 0; i < classrefList.size / 8; i++) {
           @autoreleasepool {

               unsigned long long classAddress;
               NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
               [data getBytes:&classAddress range:NSMakeRange(0, 8)];
               classAddress = [WBBladesTool getOffsetFromVmAddress:classAddress fileData:fileData];
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
                   unsigned long long targetClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.data fileData:fileData];
                   targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                   NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                   data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                   [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                   unsigned long long classNameOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.name fileData:fileData];

                   //class name 50 bytes maximum
                   uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                   [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                   NSString *className = NSSTRING(buffer);
                   free(buffer);

                   if (className) [classrefSet addObject:className];
               }
           }
       }
}

/**
 功能：读取分类中实现+load的类，在某些场景下，文件在主类中没有实现+load方法，但是在分类中实现了+load，这种场景可以通过nlcatList获取到类信息。
 classrefSet：被引用的类的集合
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 */
+ (void)readNLCatList:(section_64)nlcatList set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(nlcatList.offset, 0);
    unsigned long long max = [fileData length];
    for (int i = 0; i < nlcatList.size / 8; i++) {
        @autoreleasepool {

            unsigned long long catAddress;
            NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
            [data getBytes:&catAddress range:NSMakeRange(0, 8)];
            catAddress = [WBBladesTool getOffsetFromVmAddress:catAddress fileData:fileData];
            //method name 150 bytes maximum
            if (catAddress > 0 && catAddress < max) {

                category64 targetCategory;
                [fileData getBytes:&targetCategory range:NSMakeRange(catAddress,sizeof(category64))];

                //like UIViewController(MyCategory) +load
                if (targetCategory.cls == 0) {
                    continue;
                }
                class64 targetClass;
                [fileData getBytes:&targetClass range:NSMakeRange([WBBladesTool getOffsetFromVmAddress:targetCategory.cls fileData:fileData],sizeof(class64))];

                class64Info targetClassInfo = {0};
                unsigned long long targetClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.data fileData:fileData];
                targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                unsigned long long classNameOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.name fileData:fileData];

                //class name 50 bytes maximum
                uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                NSString *className = NSSTRING(buffer);
                free(buffer);
                if (className){
                    [classrefSet addObject:className];
                }
            }
        }
    }
}

/**
 功能：读取主类中实现+load的类，在某些场景下，文件在主类中没有实现+load方法，但是在分类中实现了+load，这种场景下该类没有在nlclsList中。
 classrefSet：被引用的类的集合
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 */
+ (void)readNLClsList:(section_64)nlclsList set:(NSMutableSet *)classrefSet fileData:(NSData *)fileData {
    //nlclslist
    NSRange range = NSMakeRange(nlclsList.offset, 0);
    unsigned long long max = [fileData length];
     for (int i = 0; i < nlclsList.size / 8; i++) {
         @autoreleasepool {

             unsigned long long classAddress;
             NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
             [data getBytes:&classAddress range:NSMakeRange(0, 8)];
             classAddress = [WBBladesTool getOffsetFromVmAddress:classAddress fileData:fileData];
             //method name 150 bytes maximum
             if (classAddress > 0 && classAddress < max) {

                 class64 targetClass;
                 [fileData getBytes:&targetClass range:NSMakeRange(classAddress,sizeof(class64))];

                 class64Info targetClassInfo = {0};
                 unsigned long long targetClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.data fileData:fileData];
                 targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
                 NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
                 data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
                 [data getBytes:&targetClassInfo length:sizeof(class64Info)];
                 unsigned long long classNameOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.name fileData:fileData];

                 //class name 50 bytes maximum
                 uint8_t *buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
                 [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
                 NSString *className = NSSTRING(buffer);
                 free(buffer);
                 if (className){
                     [classrefSet addObject:className];
                 }
             }
         }
     }
}

#pragma mark Swift
/**
 功能：查找被使用到的Swift类。主要流程如下：
 （1）获取类型，如果是类的话继续获取name；
 （2）获取到swift 类的访问函数acccessfunc;
 （3）获取类的父类名称，标记为有用类
 （4）获取类的属性类型，标记为有用类
 （5）在汇编代码中查找每个类的accessfunc，找到则标记为有用类
 swiftUsedTypeSet：被引用的类的集合
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 return：返回在遍历过程中检测出的泛型类型
 */
+ (NSArray *)readSwiftTypes:(section_64)swift5Types set:(NSMutableSet *)swiftUsedTypeSet fileData:(NSData *)fileData{

    symbols = [self getSortedSymbolList:fileData];
    //计算vm
    unsigned long long vm = swift5Types.addr - swift5Types.offset;
    NSUInteger textTypesSize = swift5Types.size;

    NSMutableArray *genericTypes = [NSMutableArray array];
    NSMutableDictionary *accessFcunDic = @{}.mutableCopy;
    for (int i = 0; i < textTypesSize / 4 ; i++) {

//出现跨段地址需要纠错，比如通过__TEXT端计算访问到__RODATA段，需要进行纠错
#define CORRECT_ADDRESS(__vmAddress)\
__vmAddress = (__vmAddress>(2*vm))?(__vmAddress-vm):__vmAddress;

        BOOL isGenericType = NO;
        unsigned long long typeAddress = swift5Types.addr + i * 4;
        uintptr_t offset = [WBBladesTool getOffsetFromVmAddress:typeAddress fileData:fileData];
        NSRange range = NSMakeRange(offset, 4);
        unsigned long long content = 0;
        [fileData getBytes:&content range:range];
        unsigned long long vmAddress = content + typeAddress;
        CORRECT_ADDRESS(vmAddress)
        unsigned long long typeOffset = [WBBladesTool getOffsetFromVmAddress:vmAddress fileData:fileData];

        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            //因为段迁移默认的权限是R&W，所以想找到text,const就只能通过Type的地址去反查
            textConst = [WBBladesTool getTEXTConst:vmAddress fileData:fileData];
        });

        SwiftType type = {0};
        range = NSMakeRange(typeOffset, sizeof(SwiftType));
        [fileData getBytes:&type range:range];

        SwiftBaseType swiftType = {0};
        range = NSMakeRange(typeOffset, sizeof(SwiftBaseType));
        [fileData getBytes:&swiftType range:range];

        isGenericType = isGenericType | [WBBladesTool isGenericType:swiftType];
        //获取名字基本都在同一个section 进行跳转，因此不会跨段
        UInt32 nameOffsetContent;
        range = NSMakeRange(typeOffset + 2 * 4, sizeof(UInt32));
        [fileData getBytes:&nameOffsetContent range:range];
        unsigned long long nameOffset = typeOffset + 2 * 4 + nameOffsetContent;
        if (nameOffset > vm) nameOffset -= vm;
        range = NSMakeRange(nameOffset, 0);
        NSString *name = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

        unsigned long long parentOffset = typeOffset + 1 * 4 + swiftType.Parent;
        if (parentOffset > vm) parentOffset = parentOffset - vm;

        if ([self invalidParent:parentOffset])continue;

        SwiftKind kind = [WBBladesTool getSwiftType:type];
        if (kind == SwiftKindOpaqueType) {
            //屏蔽swiftUI 的some修饰的类型
            continue;
        }
        while (kind != SwiftKindModule) {

            SwiftType type;
            [fileData getBytes:&type range:NSMakeRange(parentOffset, sizeof(SwiftType))];
            kind = [WBBladesTool getSwiftType:type];
            if (kind == SwiftKindUnknown) {
//                类似这样的代码（Type的Parent可能不属于Type）
//                func extensions(of value: Any) {
//                    struct Extensions : AnyExtensions {}
//                    return
//                }
                break;
            }
            isGenericType = isGenericType | [WBBladesTool isGeneric:type];

            //Anonymous 二进制布局如下：Flag(4B)+Parent(4B)+泛型签名（不定长）+mangleName(4B)
            int genericPlaceholder = 0;
            if (kind == SwiftKindAnonymous) {
                genericPlaceholder = [WBBladesTool addPlaceholderWithGeneric:parentOffset fileData:fileData];
            }
            //如果Anonymous 没有mangleName，则放弃
            if (kind == SwiftKindAnonymous && ![WBBladesTool anonymousHasMangledName:type]) {
                break;
            }

            UInt32 parentNameContent;
            [fileData getBytes:&parentNameContent range:NSMakeRange(parentOffset + 2 * 4 + genericPlaceholder, 4)];
            unsigned long long parentNameOffset = parentOffset + 2 * 4 + parentNameContent + genericPlaceholder;
            if (parentNameOffset > vm) parentNameOffset = parentNameOffset - vm;

            range = NSMakeRange(parentNameOffset, 0);

            NSString *parentName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];
            //SwiftDemo.(MyTestClass in _ACC0AAF35A10249F804F819922A1AA60) SwiftKindAnonymous竟然存的完整名称
            if (kind == SwiftKindAnonymous) {
                name = [WBBladesTool getDemangleName:parentName];
                break;
            }
            name = [NSString stringWithFormat:@"%@.%@",parentName,name];

            UInt32 parentOffsetContent;
            [fileData getBytes:&parentOffsetContent range:NSMakeRange(parentOffset + 1 * 4, 4)];
            parentOffset = parentOffset + 1 * 4 + parentOffsetContent;
            if (parentOffset > vm) parentOffset = parentOffset - vm;
            if ([self invalidParent:parentOffset])break;;
        }

        UInt32 accessFuncContent;
        range = NSMakeRange(typeOffset + 3 * 4, sizeof(UInt32));
        [fileData getBytes:&accessFuncContent range:range];
        //可能跨段
        unsigned long long accessFuncAddr = vmAddress + 3 * 4 + accessFuncContent;
        CORRECT_ADDRESS(accessFuncAddr)
        unsigned long long accessFunc = [WBBladesTool getOffsetFromVmAddress:accessFuncAddr fileData:fileData];
        if (isGenericType)[genericTypes addObject:name];

        [accessFcunDic setObject:@(accessFunc) forKey:name];

        FieldDescriptor fieldDescriptor = {0};
        unsigned long long fieldDescriptorContent = 0;

        fieldDescriptorContent = swiftType.FieldDescriptor;
        if (fieldDescriptorContent == 0) {continue;}
        unsigned long long fieldDescriptorAddress = fieldDescriptorContent + vmAddress + 4 * 4;
        CORRECT_ADDRESS(fieldDescriptorAddress)
        unsigned long long fieldDescriptorOff = [WBBladesTool getOffsetFromVmAddress:fieldDescriptorAddress fileData:fileData];
        [fileData getBytes:&fieldDescriptor range:NSMakeRange(fieldDescriptorOff, sizeof(FieldDescriptor))];

        if (fieldDescriptor.Superclass != 0) {
            unsigned long long superclassAddr = fieldDescriptorAddress + 4 * 1 + fieldDescriptor.Superclass;
            CORRECT_ADDRESS(superclassAddr)
            unsigned long long superclassOff = [WBBladesTool getOffsetFromVmAddress:superclassAddr fileData:fileData];
            char firstChar;
            [fileData getBytes:&firstChar range:NSMakeRange(superclassOff,1)];

            switch (firstChar) {
                case 0x01:
                {
                    UInt32 content = 0;
                    [fileData getBytes:&content range:NSMakeRange(superclassOff + 1,4)];

                    SwiftBaseType typeContext;
                    unsigned long long contextAddr = superclassAddr + 1 + content;
                    CORRECT_ADDRESS(contextAddr)
                    unsigned long long contextOffset = [WBBladesTool getOffsetFromVmAddress:contextAddr fileData:fileData];
                    [fileData getBytes:&typeContext range:NSMakeRange(contextOffset,sizeof(SwiftBaseType))];

                    unsigned long long nameAddr = contextAddr + 2 * 4 + typeContext.Name;
                    CORRECT_ADDRESS(nameAddr)
                    unsigned long long nameOffset = [WBBladesTool getOffsetFromVmAddress:nameAddr fileData:fileData];
                    NSRange range = NSMakeRange(nameOffset, 0);
                    NSString *mangleTypeName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

                    unsigned long long parentAddr = contextAddr + 1 * 4 + typeContext.Parent;
                    CORRECT_ADDRESS(parentAddr)
                    unsigned long long parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];

                    SwiftKind kind = SwiftKindUnknown;
                    while (kind != SwiftKindModule && ![self invalidParent:parentOffset]) {

                        SwiftType type;
                        [fileData getBytes:&type range:NSMakeRange(parentOffset, sizeof(SwiftType))];
                        kind = [WBBladesTool getSwiftType:type];
                        if (kind == SwiftKindUnknown) {
                            break;
                        }
                        int genericPlaceholder = 0;
                        if (kind == SwiftKindAnonymous) {
                            genericPlaceholder = [WBBladesTool addPlaceholderWithGeneric:parentOffset fileData:fileData];
                        }
                        //如果Anonymous 没有mangleName，则放弃
                        if (kind == SwiftKindAnonymous && ![WBBladesTool anonymousHasMangledName:type]) {
                            break;
                        }

                        UInt32 parentNameContent;
                        [fileData getBytes:&parentNameContent range:NSMakeRange(parentOffset + 2 * 4 + genericPlaceholder, 4)];

                        unsigned long long parentNameAddr = parentAddr + 2 * 4 + parentNameContent + genericPlaceholder;
                        CORRECT_ADDRESS(parentNameAddr)
                        unsigned long long parentNameOffset = [WBBladesTool getOffsetFromVmAddress:parentNameAddr fileData:fileData];

                        range = NSMakeRange(parentNameOffset, 0);

                        NSString *parentName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];
                        //SwiftDemo.(MyTestClass in _ACC0AAF35A10249F804F819922A1AA60) SwiftKindAnonymous竟然存的完整名称
                        if (kind == SwiftKindAnonymous) {
                            mangleTypeName = [WBBladesTool getDemangleName:parentName];
                            break;
                        }
                        mangleTypeName = [NSString stringWithFormat:@"%@.%@",parentName,mangleTypeName];
                        UInt32 parentOffsetContent;
                        [fileData getBytes:&parentOffsetContent range:NSMakeRange(parentOffset + 1 * 4, 4)];

                        parentAddr = parentAddr + 1 * 4 + parentOffsetContent;
                        CORRECT_ADDRESS(parentAddr)
                        parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];
                    }
                    [swiftUsedTypeSet addObject:mangleTypeName];
                }
                    break;
                case 0x02:
                {
                    UInt32 content = 0;
                    [fileData getBytes:&content range:NSMakeRange(superclassOff + 1,4)];

                    SwiftBaseType typeContext;
                    unsigned long long indirectContextAddr = superclassAddr + 1 + content;
                    CORRECT_ADDRESS(indirectContextAddr)
                    unsigned long long indirectContextOffset = [WBBladesTool getOffsetFromVmAddress:indirectContextAddr fileData:fileData];

                    unsigned long long contextAddress = 0;
                    [fileData getBytes:&contextAddress range:NSMakeRange(indirectContextOffset , 8)];

                    if (contextAddress == 0)continue;

                    CORRECT_ADDRESS(contextAddress)
                    unsigned long long contextOff = [WBBladesTool getOffsetFromVmAddress:contextAddress fileData:fileData];
                    [fileData getBytes:&typeContext range:NSMakeRange(contextOff,sizeof(SwiftBaseType))];

                    unsigned long long nameOffAddr = contextAddress + 2 * 4 + typeContext.Name;
                    CORRECT_ADDRESS(nameOffAddr)
                    unsigned long long nameOffset = [WBBladesTool getOffsetFromVmAddress:nameOffAddr fileData:fileData];
                    NSRange range = NSMakeRange(nameOffset, 0);
                    NSString *mangleTypeName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

                    unsigned long long parentAddr = contextAddress + 1 * 4 + typeContext.Parent;
                    CORRECT_ADDRESS(parentAddr)
                    unsigned long long parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];

                    SwiftKind kind = SwiftKindUnknown;
                    while (kind != SwiftKindModule && ![self invalidParent:parentOffset]) {

                        SwiftType type;
                        [fileData getBytes:&type range:NSMakeRange(parentOffset, sizeof(SwiftType))];
                        kind = [WBBladesTool getSwiftType:type];
                        if (kind == SwiftKindUnknown) {
                            break;
                        }
                        int genericPlaceholder = 0;
                        if (kind == SwiftKindAnonymous) {
                            genericPlaceholder = [WBBladesTool addPlaceholderWithGeneric:parentOffset fileData:fileData];
                        }
                        //如果Anonymous 没有mangleName，则放弃
                        if (kind == SwiftKindAnonymous && ![WBBladesTool anonymousHasMangledName:type]) {
                            break;
                        }
                        UInt32 parentNameContent;
                        [fileData getBytes:&parentNameContent range:NSMakeRange(parentOffset + 2 * 4 + genericPlaceholder, 4)];

                        unsigned long long parentNameAddr = parentAddr + 2 * 4 + parentNameContent + genericPlaceholder;
                        CORRECT_ADDRESS(parentNameAddr)
                        unsigned long long parentNameOffset = [WBBladesTool getOffsetFromVmAddress:parentNameAddr fileData:fileData];

                        range = NSMakeRange(parentNameOffset, 0);

                        NSString *parentName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];
                        //SwiftDemo.(MyTestClass in _ACC0AAF35A10249F804F819922A1AA60) SwiftKindAnonymous竟然存的完整名称
                        if (kind == SwiftKindAnonymous) {
                            mangleTypeName = [WBBladesTool getDemangleName:parentName];
                            break;
                        }
                        mangleTypeName = [NSString stringWithFormat:@"%@.%@",parentName,mangleTypeName];
                        UInt32 parentOffsetContent;
                        [fileData getBytes:&parentOffsetContent range:NSMakeRange(parentOffset + 1 * 4, 4)];

                        parentAddr = parentAddr + 1 * 4 + parentOffsetContent;
                        CORRECT_ADDRESS(parentAddr)
                        parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];
                    }
                    [swiftUsedTypeSet addObject:mangleTypeName];
                }
                    break;
                default:
                {
                    NSRange range = NSMakeRange(superclassOff, 0);
                    NSString *superName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];
                    if (superName.length <= 13 && superName.length >= 5) {
                        superName = [superName substringWithRange:NSMakeRange(3,superName.length - 4)];
                    }else if (superName.length <= 104 && superName.length >= 15){
                        superName = [superName substringWithRange:NSMakeRange(4,superName.length - 5)];
                    }
                    [swiftUsedTypeSet addObject:superName];
                }
                    break;
            }
        }
        unsigned long long  fieldRecordAddr = fieldDescriptorAddress + sizeof(FieldDescriptor);
        unsigned long long  fieldRecordOff =  fieldDescriptorOff + sizeof(FieldDescriptor);
        for (int j = 0; j < fieldDescriptor.NumFields; j++) {

            BOOL isGenericFiled = NO;

//          https://github.com/apple/swift/blob/7123d2614b5f222d03b3762cb110d27a9dd98e24/include/swift/Reflection/Records.h
            FieldRecord record = {0};
            [fileData getBytes:&record range:NSMakeRange(fieldRecordOff, sizeof(FieldRecord))];
            //0x0 泛型属性 例如：let name: ClassA<String>? = nil
            if (record.Flags != FieldRecordFlag_IsVar && record.Flags != 0x0) {
                continue;
            }

            unsigned long long mangleNameAddr = fieldRecordAddr + (record.MangledTypeName) + 1 * 4;
            CORRECT_ADDRESS(mangleNameAddr)
            unsigned long long mangleNameOffset = [WBBladesTool getOffsetFromVmAddress:mangleNameAddr fileData:fileData];

            fieldRecordAddr += sizeof(FieldRecord);
            fieldRecordOff += sizeof(FieldRecord);

            char firstChar;
            [fileData getBytes:&firstChar range:NSMakeRange(mangleNameOffset,1)];

            switch (firstChar) {
                case 0x01:
                {
                    UInt32 content = 0;
                    [fileData getBytes:&content range:NSMakeRange(mangleNameOffset + 1,4)];

                    SwiftBaseType typeContext;
                    unsigned long long contextAddr = mangleNameAddr + 1 + content;
                    CORRECT_ADDRESS(contextAddr)
                    unsigned long long contextOffset = [WBBladesTool getOffsetFromVmAddress:contextAddr fileData:fileData];
                    [fileData getBytes:&typeContext range:NSMakeRange(contextOffset,sizeof(SwiftBaseType))];

                    isGenericFiled = isGenericFiled | [WBBladesTool isGenericType:typeContext];

                    unsigned long long nameAddr = contextAddr + 2 * 4 + typeContext.Name;
                    CORRECT_ADDRESS(nameAddr)
                    unsigned long long nameOffset = [WBBladesTool getOffsetFromVmAddress:nameAddr fileData:fileData];
                    NSRange range = NSMakeRange(nameOffset, 0);
                    NSString *mangleTypeName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

                    unsigned long long parentAddr = contextAddr + 1 * 4 + typeContext.Parent;
                    CORRECT_ADDRESS(parentAddr)
                    unsigned long long parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];

                    SwiftKind kind = SwiftKindUnknown;
                    while (kind != SwiftKindModule && ![self invalidParent:parentOffset]) {

                        SwiftType type;
                        [fileData getBytes:&type range:NSMakeRange(parentOffset, sizeof(SwiftType))];
                        kind = [WBBladesTool getSwiftType:type];
                        if (kind == SwiftKindUnknown) {
                            break;
                        }
                        isGenericFiled = isGenericFiled | [WBBladesTool isGeneric:type];
                        int genericPlaceholder = 0;
                        if (kind == SwiftKindAnonymous) {
                            genericPlaceholder = [WBBladesTool addPlaceholderWithGeneric:parentOffset fileData:fileData];
                        }
                        //如果Anonymous 没有mangleName，则放弃
                        if (kind == SwiftKindAnonymous && ![WBBladesTool anonymousHasMangledName:type]) {
                            break;
                        }
                        UInt32 parentNameContent;
                        [fileData getBytes:&parentNameContent range:NSMakeRange(parentOffset + 2 * 4 + genericPlaceholder, 4)];

                        unsigned long long parentNameAddr = parentAddr + 2 * 4 + parentNameContent + genericPlaceholder;
                        CORRECT_ADDRESS(parentNameAddr)
                        unsigned long long parentNameOffset = [WBBladesTool getOffsetFromVmAddress:parentNameAddr fileData:fileData];

                        range = NSMakeRange(parentNameOffset, 0);

                        NSString *parentName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

                        //SwiftDemo.(MyTestClass in _ACC0AAF35A10249F804F819922A1AA60) SwiftKindAnonymous竟然存的完整名称
                        if (kind == SwiftKindAnonymous) {
                            mangleTypeName = [WBBladesTool getDemangleName:parentName];
                            break;
                        }
                        mangleTypeName = [NSString stringWithFormat:@"%@.%@",parentName,mangleTypeName];
                        UInt32 parentOffsetContent;
                        [fileData getBytes:&parentOffsetContent range:NSMakeRange(parentOffset + 1 * 4, 4)];

                        parentAddr = parentAddr + 1 * 4 + parentOffsetContent;
                        CORRECT_ADDRESS(parentAddr)
                        parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];
                    }
                    if (isGenericFiled)[genericTypes addObject:mangleTypeName];
                    [swiftUsedTypeSet addObject:mangleTypeName];
                    break;
                }
                case 0x02:
                {
                    UInt32 content = 0;
                    [fileData getBytes:&content range:NSMakeRange(mangleNameOffset + 1,4)];

                    SwiftBaseType typeContext;

                    unsigned long long indirectContextAddr = mangleNameAddr + 1 + content;
                    CORRECT_ADDRESS(indirectContextAddr)
                    unsigned long long indirectContextOffset = [WBBladesTool getOffsetFromVmAddress:indirectContextAddr fileData:fileData];
                    unsigned long long contextAddress = 0;
                    [fileData getBytes:&contextAddress range:NSMakeRange(indirectContextOffset , 8)];

                    if (contextAddress == 0)continue;

                    CORRECT_ADDRESS(contextAddress)
                    unsigned long long contextOff = [WBBladesTool getOffsetFromVmAddress:contextAddress fileData:fileData];
                    [fileData getBytes:&typeContext range:NSMakeRange(contextOff,sizeof(SwiftBaseType))];

                    isGenericFiled = isGenericFiled | [WBBladesTool isGenericType:typeContext];

                    unsigned long long nameAddr = contextAddress + 2 * 4 + typeContext.Name;
                    CORRECT_ADDRESS(nameAddr)
                    unsigned long long nameOffset = [WBBladesTool getOffsetFromVmAddress:nameAddr fileData:fileData];
                    NSRange range = NSMakeRange(nameOffset, 0);
                    NSString *mangleTypeName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];

                    unsigned long long parentAddr = contextAddress + 1 * 4 + typeContext.Parent;
                    CORRECT_ADDRESS(parentAddr)
                    unsigned long long parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];

                    SwiftKind kind = SwiftKindUnknown;
                    while (kind != SwiftKindModule && ![self invalidParent:parentOffset]) {

                        SwiftType type;
                        [fileData getBytes:&type range:NSMakeRange(parentOffset, sizeof(SwiftType))];
                        kind = [WBBladesTool getSwiftType:type];
                        if (kind == SwiftKindUnknown) {
                            break;
                        }
                        isGenericFiled = isGenericFiled | [WBBladesTool isGeneric:type];
                        int genericPlaceholder = 0;
                        if (kind == SwiftKindAnonymous) {
                            genericPlaceholder = [WBBladesTool addPlaceholderWithGeneric:parentOffset fileData:fileData];
                        }
                        //如果Anonymous 没有mangleName，则放弃
                        if (kind == SwiftKindAnonymous && ![WBBladesTool anonymousHasMangledName:type]) {
                            break;
                        }
                        UInt32 parentNameContent;
                        [fileData getBytes:&parentNameContent range:NSMakeRange(parentOffset + 2 * 4 + genericPlaceholder, 4)];
                        unsigned long long parentNameAddr = parentAddr + 2 * 4 + parentNameContent + genericPlaceholder;
                        CORRECT_ADDRESS(parentNameAddr)
                        unsigned long long parentNameOffset = [WBBladesTool getOffsetFromVmAddress:parentNameAddr fileData:fileData];

                        range = NSMakeRange(parentNameOffset, 0);

                        NSString *parentName = [WBBladesTool readString:range fixlen:150 fromFile:fileData];
                        //SwiftDemo.(MyTestClass in _ACC0AAF35A10249F804F819922A1AA60) SwiftKindAnonymous竟然存的完整名称
                        if (kind == SwiftKindAnonymous) {
                            mangleTypeName = [WBBladesTool getDemangleName:parentName];
                            break;
                        }
                        mangleTypeName = [NSString stringWithFormat:@"%@.%@",parentName,mangleTypeName];
                        UInt32 parentOffsetContent;
                        [fileData getBytes:&parentOffsetContent range:NSMakeRange(parentOffset + 1 * 4, 4)];

                        parentAddr = parentAddr + 1 * 4 + parentOffsetContent;
                        CORRECT_ADDRESS(parentAddr)
                        parentOffset = [WBBladesTool getOffsetFromVmAddress:parentAddr fileData:fileData];
                    }
                    if (isGenericFiled)[genericTypes addObject:mangleTypeName];
                    [swiftUsedTypeSet addObject:mangleTypeName];

                    break;
                }
                case 0x09:
                    break;
                default:
                    break;
            }
        }
    }

    //一些type 直接记录了metadata的地址，无需通过accessfun 调用
    NSDictionary *cacheMetaDic = [self readSwiftCacheMetadata:fileData];

    //查找access调用
    NSLock *locker = [[NSLock alloc] init];
    NSArray *allKeys = accessFcunDic.allKeys;
//    dispatch_apply(allKeys.count, dispatch_get_global_queue(0, 0), ^(size_t index) {
    for(int i=0; i<allKeys.count; i++) {
        @autoreleasepool {
            NSString *name = allKeys[i];
            unsigned long long accessFunc = [accessFcunDic[name] unsignedLongLongValue];
            unsigned long long cache = [cacheMetaDic[name] unsignedLongLongValue];
            if (cache > 0) {
                accessFunc = cache;
            }
            accessFunc = accessFunc > vm ? accessFunc - vm : accessFunc;
            if ([self findCallAccessFunc:name accessFunc:accessFunc fileData:fileData]) {
                [locker lock];
                [swiftUsedTypeSet addObject:name];
                [locker unlock];
            }
        }
    }

//    });

    return genericTypes.copy;
}

/**
 功能：判断某个类型的Parent 的偏移地址是否合法，如果合法则可以继续当前流程，否则中断遍历
 parentOff：某个类型的Parent 的偏移地址
 return：YES合法，NO不合理的值
 */
+ (BOOL)invalidParent:(UInt64)parentOff{
    if (parentOff >= textConst.offset && parentOff < textConst.offset + textConst.size ) {
        return NO;
    }
    return YES;
}

/**
 功能：在汇编代码中查找Swift类的AccessFunc是否有调用。在符号表中进行判断是否为Swift类型，如果是Swift类型的函数的话才会在其汇编代码中搜索。
 typeName：当前正在检测是否有用的Swift类
 accessFunc：当前正在检测是否有用的Swift类的访问函数AccessFunc
 return：YES:Swift类被检测到有被使用 NO:Swift类没有被使用
 */
+ (BOOL)findCallAccessFunc:(NSString *)typeName accessFunc:(unsigned long long)accessFunc  fileData:(NSData *)fileData {
    NSString *demangleName = [WBBladesTool getDemangleName:typeName];

    //target address
    char *targetStr = (char *)[[[NSString stringWithFormat:@"#0x%llX",accessFunc] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];

    //target high address
    char *targetHighStr =(char *) [[[NSString stringWithFormat:@"#0x%llX",accessFunc & 0xFFFFFFFFFFFFF000] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];

    //Target low address
    char *targetLowStr = (char *)[[[NSString stringWithFormat:@"#0x%llX",accessFunc & 0x0000000000000fff] lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];

    for (int i = 0; i < symbols.count; i++) {
        WBBladesSymbolRange *symRanObj = (WBBladesSymbolRange*)symbols[i];
        if (symRanObj.symbol.length == 0 ) {
            continue;
        }
        if ([symRanObj.symbol hasPrefix:typeName] || [symRanObj.symbol hasPrefix:demangleName]) {
            continue;
        }
        if ([symRanObj.symbol containsString:@"ViewController"]) {

        }
        BOOL find = [self scanSELCallerWithAddress:targetStr heigh:targetHighStr low:targetLowStr begin:symRanObj.begin end:symRanObj.end];
        if (find) return YES;
    }
    return NO;
}

/**
 功能：泛型的约束需要被当做有用代码，因此通过符号表检测出所有泛型的约束条件，并解析出对应的类型名称放入到有用类集合中。
 swiftUsedTypeSet：有用类集合
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 return：泛型集合
 */
+ (NSArray *)readSwiftGenericRequire:(NSMutableSet *)swiftUsedTypeSet fileData:(NSData *)fileData{
    WBBladesSymTabCommand *symCmd = [self symbolTabOffsetWithMachO:fileData];
    ptrdiff_t symbolOffset = symCmd.symbolOff;
    NSMutableSet *genericRequiredSet = [NSMutableSet set];
    for (int i=0; i < symCmd.symbolNum ; i++) {
        nlist_64 nlist;
        ptrdiff_t off = symbolOffset + i * sizeof(nlist_64);
        char *p = (char *)fileData.bytes;
        p = p + off;
        memcpy(&nlist, p, sizeof(nlist_64));
        if (([WBBladesTool sectionFlagsWithIndex:nlist.n_sect fileData:fileData] & (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) != (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)){
            char buffer[201];
            ptrdiff_t off = symCmd.strOff+nlist.n_un.n_strx;
            char * p = (char *)fileData.bytes;
            p = p+off;
            memcpy(&buffer, p, 200);
            NSString *symbol = [WBBladesTool getDemangleNameWithCString:buffer];
            if ([symbol hasPrefix:METADATACACHE_FLAG]) {
                NSString *cacheMetadata = [symbol substringFromIndex:METADATACACHE_FLAG.length];
                NSArray *tmp = [cacheMetadata componentsSeparatedByString:@"<"];
                if (tmp.count > 1) {//有泛型约束
                    NSString *genericRequire = [tmp lastObject];
                    genericRequire = [genericRequire stringByReplacingOccurrencesOfString:@">" withString:@""];
                    NSArray *types = [genericRequire componentsSeparatedByString:@", "];
                    [genericRequiredSet addObjectsFromArray:types];
                    [swiftUsedTypeSet addObjectsFromArray:types];
                }
            }
        }
    }
    return genericRequiredSet.allObjects;
}

/**
 功能：从符号表中读取数据，如果符号以"demangling cache variable for type metadata for "开头，说明该类型符号没有AccessFunc的调用而是直接使用Metadata的地址。
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 return：{ 类名: Metadata地址 }
 */
+ (NSDictionary *)readSwiftCacheMetadata:(NSData *)fileData{
    WBBladesSymTabCommand *symCmd = [self symbolTabOffsetWithMachO:fileData];
    ptrdiff_t symbolOffset = symCmd.symbolOff;
    NSMutableDictionary *dic = @{}.mutableCopy;
    for (int i=0; i < symCmd.symbolNum ; i++) {
        nlist_64 nlist;
        ptrdiff_t off = symbolOffset + i * sizeof(nlist_64);
        char *p = (char *)fileData.bytes;
        p = p + off;
        memcpy(&nlist, p, sizeof(nlist_64));
        if (([WBBladesTool sectionFlagsWithIndex:nlist.n_sect fileData:fileData] & (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) != (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)){
            char buffer[201];
            ptrdiff_t off = symCmd.strOff+nlist.n_un.n_strx;
            char * p = (char *)fileData.bytes;
            p = p+off;
            memcpy(&buffer, p, 200);
            NSString *symbol = [WBBladesTool getDemangleNameWithCString:buffer];
            if ([symbol hasPrefix:METADATACACHE_FLAG]) {
                NSString *cacheMetadata = [symbol substringFromIndex:METADATACACHE_FLAG.length];
                NSArray *tmp = [cacheMetadata componentsSeparatedByString:@"<"];
                NSString *typeName = [tmp firstObject];
                if (nlist.n_value > 0 && typeName.length > 0) {
                    [dic setObject:@(nlist.n_value) forKey:typeName];
                }
            }
        }
    }
    return dic.copy;
}

/**
 功能：读取符号表，并对符号表按地址进行排序。处理后可以得到每个符号的地址区间。
 fileData：从磁盘中读取的二进制文件，通常是可执行文件。
 return：WBBladesSymbolRange 对象数组
 */
+ (NSArray *)getSortedSymbolList:(NSData *)fileData{
    WBBladesSymTabCommand *symCmd = [self symbolTabOffsetWithMachO:fileData];
    ptrdiff_t symbolOffset = symCmd.symbolOff;
    NSMutableDictionary *dic = @{}.mutableCopy;
    for (int i=0; i < symCmd.symbolNum ; i++) {
        @autoreleasepool {
            nlist_64 nlist;
            ptrdiff_t off = symbolOffset + i * sizeof(nlist_64);
            char *p = (char *)fileData.bytes;
            p = p + off;
            memcpy(&nlist, p, sizeof(nlist_64));
            if (([WBBladesTool sectionFlagsWithIndex:nlist.n_sect fileData:fileData] & (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) == (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) {
                char buffer[201];
                ptrdiff_t off = symCmd.strOff+nlist.n_un.n_strx;
                char * p = (char *)fileData.bytes;
                p = p+off;
                memcpy(&buffer, p, 200);
                NSString *symbol = [NSString stringWithFormat:@"%s",buffer];
                if ([symbol isEqualToString:@"__mh_execute_header"]) {
                    continue;
                }
                if ([symbol hasPrefix:@"-"] || [symbol hasPrefix:@"+"]) {
                    continue;
                }
                unsigned long long offset = nlist.n_value;
                [dic setObject:@(offset) forKey:symbol];
            }
        }
    }
    NSArray *offsets = [dic keysSortedByValueUsingComparator:^NSComparisonResult(id  _Nonnull obj1, id  _Nonnull obj2) {
        @autoreleasepool {
            NSNumber *number1 = (NSNumber *)obj1;
            NSNumber *number2 = (NSNumber *)obj2;

            if ([number1 unsignedLongLongValue] > [number2 unsignedLongLongValue]) {
                return NSOrderedDescending;
            }else{
                return NSOrderedAscending;
            }
        }
    }];
    NSMutableArray *allSymbols = [NSMutableArray array];
    [offsets enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {

        @autoreleasepool {
            WBBladesSymbolRange *symRanObj = [WBBladesSymbolRange new];
            unsigned long long begin = [[dic objectForKey:obj] unsignedLongLongValue];
            if (begin > 0) {
                NSString *symbol = [WBBladesTool getDemangleName:obj];
                if (symbol.length > 0) {
                    symRanObj.symbol = symbol;
                }else{
                    symRanObj.symbol = obj;
                }
                symRanObj.begin = begin;
                if (idx < offsets.count - 1) {
                    symRanObj.end = [[dic objectForKey:offsets[idx + 1]] unsignedLongLongValue];
                }else{
                    symRanObj.end = 0;
                }
                [self trimSwiftSymbol:symRanObj];
                [allSymbols addObject:symRanObj];
            }
        }
    }];
    return allSymbols.copy;
}

/**
 功能：剔除符号开头的“static ”。
 symRanObj：WBBladesSymbolRange类型模型。
 */
+ (void)trimSwiftSymbol:(WBBladesSymbolRange *)symRanObj{
    NSString *tripStr = @"static ";
    if ([symRanObj.symbol hasPrefix:tripStr]) {
        symRanObj.symbol = [symRanObj.symbol substringFromIndex:tripStr.length];
    }
}

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
                    NSLog(@"Swift无用代码检测依赖Debug包的符号表，检测到您的包里没有符号表，建议使用arm64真机的debug包扫描");
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

