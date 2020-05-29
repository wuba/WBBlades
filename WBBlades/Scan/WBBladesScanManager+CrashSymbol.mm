//
//  WBBladesScanManager+CrashSymbol.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager+CrashSymbol.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>

#import "WBBladesTool.h"
#import "WBBladesDefines.h"

@implementation WBBladesScanManager (CrashSymbol)

+ (NSDictionary *)symbolizeWithMachOFile:(NSData *)fileData crashOffsets:(NSString *)crashAddresses {
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    section_64 classList = {0};
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];
            
            //遍历查找classlist
            if ([segName isEqualToString:SEGMENT_DATA] ||
                [segName isEqualToString:SEGMENT_DATA_CONST]) {
                //遍历所有的section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    if ([secName isEqualToString:DATA_CLASSLIST_SECTION] ||
                        [secName isEqualToString:CONST_DATA_CLASSLIST_SECTION]) {
                        classList = sectionHeader;
                    }
                    currentSecLocation += sizeof(section_64);
                }
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    NSDictionary *crashSymbolRst = [self scanCrashSymbolResult:classList fileData:fileData crashOffsets:crashAddresses];
    
    NSData *resultsData = [NSJSONSerialization dataWithJSONObject:crashSymbolRst options:NSJSONWritingPrettyPrinted error:nil];
    NSString *resultsJson = [[NSString alloc] initWithData:resultsData encoding:NSUTF8StringEncoding];
    [resultsJson writeToFile:@"/dev/stdout" atomically:NO encoding:NSUTF8StringEncoding error:nil];
    return crashSymbolRst;
}

+ (NSDictionary *)scanCrashSymbolResult:(section_64)classList fileData:(NSData*)fileData crashOffsets:(NSString *)crashAddresses{
    unsigned long long max = [fileData length];
    unsigned long long vm = classList.addr - classList.offset;
    
    static NSMutableDictionary *crashSymbolRst = @{}.mutableCopy;
    //获取所有类classlist
    NSRange range = NSMakeRange(classList.offset, 0);
    for (int i = 0; i < classList.size / 8 ; i++) {
        @autoreleasepool {
            unsigned long long classAddress;
            NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
            [data getBytes:&classAddress range:NSMakeRange(0, 8)];
            unsigned long long classOffset = classAddress - vm;
            
            class64 targetClass = {0};
            NSRange targetClassRange = NSMakeRange(classOffset, 0);
            data = [WBBladesTool readBytes:targetClassRange length:sizeof(class64) fromFile:fileData];
            [data getBytes:&targetClass length:sizeof(class64)];
            
            class64Info targetClassInfo = {0};
            unsigned long long targetClassInfoOffset = targetClass.data - vm;
            targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
            NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
            data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
            [data getBytes:&targetClassInfo length:sizeof(class64Info)];
            unsigned long long classNameOffset = targetClassInfo.name - vm;
            
            class64 metaClass = {0};
            NSRange metaClassRange = NSMakeRange(targetClass.isa - vm, 0);
            data = [WBBladesTool readBytes:metaClassRange length:sizeof(class64) fromFile:fileData];
            [data getBytes:&metaClass length:sizeof(class64)];
            
            class64Info metaClassInfo = {0};
            unsigned long long metaClassInfoOffset = metaClass.data - vm;
            metaClassInfoOffset = (metaClassInfoOffset / 8) * 8;
            NSRange metaClassInfoRange = NSMakeRange(metaClassInfoOffset, 0);
            data = [WBBladesTool readBytes:metaClassInfoRange length:sizeof(class64Info) fromFile:fileData];
            [data getBytes:&metaClassInfo length:sizeof(class64Info)];
            
            unsigned long long methodListOffset = targetClassInfo.baseMethods - vm;
            unsigned long long classMethodListOffset = metaClassInfo.baseMethods - vm;
            
            //类名最大50字节
            uint8_t * buffer = (uint8_t *)malloc(CLASSNAME_MAX_LEN + 1); buffer[CLASSNAME_MAX_LEN] = '\0';
            [fileData getBytes:buffer range:NSMakeRange(classNameOffset, CLASSNAME_MAX_LEN)];
            NSString * className = NSSTRING(buffer);
            free(buffer);

            NSArray *crashAddress = [crashAddresses componentsSeparatedByString:@","];
            //遍历每个class的method (实例方法)
            if (methodListOffset > 0 && methodListOffset < max) {
                NSDictionary *methodRst = [self scanMethodListResult:methodListOffset
                                                           className:className
                                                                  vm:vm
                                                                data:data
                                                            fileData:fileData
                                                        crashAddress:crashAddress];
                [crashSymbolRst addEntriesFromDictionary:methodRst];
            }
            //类方法
            if (classMethodListOffset > 0 && classMethodListOffset < max) {
                NSDictionary *classMethodRst = [self scanClassMethodListResult:classMethodListOffset
                                                                     className:className
                                                                            vm:vm
                                                                          data:data
                                                                      fileData:fileData
                                                                  crashAddress:crashAddress];
                [crashSymbolRst addEntriesFromDictionary:classMethodRst];
            }
        }
    }
    return crashSymbolRst.copy;
}

+ (NSDictionary *)scanMethodListResult:(unsigned long long)methodListOffset
                            className:(NSString*)className
                                   vm:(unsigned long long)vm
                                 data:(NSData*)data
                             fileData:(NSData*)fileData
                         crashAddress:(NSArray *)crashAddress{
    
    unsigned long long max = [fileData length];
    method64_list_t methodList;
    
    NSRange methodRange = NSMakeRange(methodListOffset, 0);
    data = [WBBladesTool readBytes:methodRange length:sizeof(method64_list_t) fromFile:fileData];
    [data getBytes:&methodList length:sizeof(method64_list_t)];
    
    NSMutableDictionary *crashSymbolRst = [NSMutableDictionary dictionary];
    for (int j = 0; j<methodList.count; j++) {
        
        //获取方法名
        methodRange = NSMakeRange(methodListOffset + sizeof(method64_list_t) + sizeof(method64_t) * j, 0);
        data = [WBBladesTool readBytes:methodRange length:sizeof(method64_t) fromFile:fileData];
        
        method64_t method;
        [data getBytes:&method length:sizeof(method64_t)];
        unsigned long long methodNameOffset = method.name - vm;
        
        //方法名最大150字节
        uint8_t * buffer = (uint8_t *)malloc(METHODNAME_MAX_LEN + 1); buffer[METHODNAME_MAX_LEN] = '\0';
        if (methodNameOffset > 0 && methodNameOffset < max) {
            [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,METHODNAME_MAX_LEN)];
            NSString * methodName = NSSTRING(buffer);
            
            unsigned long long imp = method.imp;
            NSLog(@"遍历 -[%@ %@]",className,methodName);
            [crashAddress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                unsigned long long crash = [(NSString *)obj longLongValue];
                if ([self scanFuncBinaryCode:crash begin:imp vm:vm fileData:fileData]) {
                    NSString *key = [NSString stringWithFormat:@"%lld",crash];
                    if (!crashSymbolRst[key] || [crashSymbolRst[key][IMP_KEY] longLongValue] < imp) {
                        NSMutableDictionary *dic = @{IMP_KEY:@(imp),SYMBOL_KEY:[NSString stringWithFormat:@"-[%@ %@]",className,methodName]}.mutableCopy;
                        [crashSymbolRst setObject:dic forKey:key];
                    }
                }
            }];
        }
        free(buffer);
    }
    return crashSymbolRst.copy;
}

+ (NSDictionary *)scanClassMethodListResult:(unsigned long long)classMethodListOffset
                                  className:(NSString*)className
                                         vm:(unsigned long long)vm
                                       data:(NSData*)data
                                   fileData:(NSData*)fileData
                               crashAddress:(NSArray *)crashAddress{
    unsigned long long max = [fileData length];
    method64_list_t methodList;
    
    NSRange methodRange = NSMakeRange(classMethodListOffset, 0);
    data = [WBBladesTool readBytes:methodRange length:sizeof(method64_list_t) fromFile:fileData];
    [data getBytes:&methodList length:sizeof(method64_list_t)];
    
    NSMutableDictionary *crashSymbolRst = [NSMutableDictionary dictionary];
    for (int j = 0; j<methodList.count; j++) {
        
        //获取方法名
        method64_t method;
        methodRange = NSMakeRange(classMethodListOffset+sizeof(method64_list_t) + sizeof(method64_t) * j, 0);
        data = [WBBladesTool readBytes:methodRange length:sizeof(method64_t) fromFile:fileData];
        
        [data getBytes:&method length:sizeof(method64_t)];
        unsigned long long methodNameOffset = method.name - vm;
        
        //方法名最大150字节
        uint8_t * buffer = (uint8_t *)malloc(METHODNAME_MAX_LEN + 1); buffer[METHODNAME_MAX_LEN] = '\0';
        if (methodNameOffset > 0 && methodNameOffset < max) {
            [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,METHODNAME_MAX_LEN)];
            NSString * methodName = NSSTRING(buffer);
                                
            unsigned long long imp = method.imp;
            NSLog(@"遍历 +[%@ %@]",className,methodName);
            [crashAddress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                unsigned long long crash = [(NSString *)obj longLongValue];
                if ([self scanFuncBinaryCode:crash begin:imp vm:vm fileData:fileData] ) {
                    NSString *key = [NSString stringWithFormat:@"%lld",crash];
                    if (!crashSymbolRst[key] || [crashSymbolRst[key][IMP_KEY] longLongValue] < imp) {
                        NSMutableDictionary *dic = @{IMP_KEY:@(imp),SYMBOL_KEY:[NSString stringWithFormat:@"+[%@ %@]",className,methodName]}.mutableCopy;
                        [crashSymbolRst setObject:dic forKey:key];
                    }
                }
            }];
        }
        free(buffer);
    }
    return crashSymbolRst.copy;
}

+ (BOOL)scanFuncBinaryCode:(unsigned long long)target  begin:(unsigned long long)begin  vm:(unsigned long long )vm fileData:(NSData*)fileData {
    if (begin > target + vm) {
        return NO;
    }
    
    unsigned int asmCode = 0;
    do {
        [fileData getBytes:&asmCode range:NSMakeRange(begin - vm, 4)];
        if (begin == target + vm) {
            return YES;
        }
        begin += 4;
    } while (asmCode != RET);
    return NO;
}

@end
