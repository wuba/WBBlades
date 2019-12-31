//
//  WBBladesScanManager+CrashSymbol.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/30.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager+CrashSymbol.h"
#import "WBBladesScanManager.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#import "WBBladesTool.h"
#import "WBBladesDefines.h"

@implementation WBBladesScanManager (CrashSymbol)

+ (void)scanAllClassMethodList:(NSData *)fileData crashPlistPath:(NSString *)crashAddressPath{
    
    unsigned long long max = [fileData length];
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
            
            //遍历查找classlist、selref、classref、nlcls、cfstring section
            if ([segName isEqualToString:@"__DATA"]) {
                //遍历所有的section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {
                    
                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];
                    
                    if ([secName isEqualToString:@"__objc_classlist__DATA"]) {
                        classList = sectionHeader;
                    }
                    
                    currentSecLocation += sizeof(section_64);
                }
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    unsigned long long vm = classList.addr - classList.offset;
    
    static NSMutableDictionary *crashSymbolRst = @{}.mutableCopy;
    //获取所有类classlist
    NSRange range = NSMakeRange(classList.offset, 0);
    for (int i = 0; i < classList.size / 8 ; i++) {
    @autoreleasepool {
        
        unsigned long long classAddress;
        NSData *data = [WBBladesTool read_bytes:range length:8 fromFile:fileData];
        [data getBytes:&classAddress range:NSMakeRange(0, 8)];
        unsigned long long classOffset = classAddress - vm;
        
        class64 targetClass = {0};
        NSRange targetClassRange = NSMakeRange(classOffset, 0);
        data = [WBBladesTool read_bytes:targetClassRange length:sizeof(class64) fromFile:fileData];
        [data getBytes:&targetClass length:sizeof(class64)];
        
        class64Info targetClassInfo = {0};
        unsigned long long targetClassInfoOffset = targetClass.data - vm;
        NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
        data = [WBBladesTool read_bytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
        [data getBytes:&targetClassInfo length:sizeof(class64Info)];
        unsigned long long classNameOffset = targetClassInfo.name - vm;
        
        
        class64 metaClass = {0};
        NSRange metaClassRange = NSMakeRange(targetClass.isa - vm, 0);
        data = [WBBladesTool read_bytes:metaClassRange length:sizeof(class64) fromFile:fileData];
        [data getBytes:&metaClass length:sizeof(class64)];
        
        class64Info metaClassInfo = {0};
        unsigned long long metaClassInfoOffset = metaClass.data - vm;
        NSRange metaClassInfoRange = NSMakeRange(metaClassInfoOffset, 0);
        data = [WBBladesTool read_bytes:metaClassInfoRange length:sizeof(class64Info) fromFile:fileData];
        [data getBytes:&metaClassInfo length:sizeof(class64Info)];
        
        
        unsigned long long methodListOffset = targetClassInfo.baseMethods - vm;
        unsigned long long classMethodListOffset = metaClassInfo.baseMethods - vm;
        
        //类名最大50字节
        uint8_t * buffer = (uint8_t *)malloc(50 + 1); buffer[50] = '\0';
        [fileData getBytes:buffer range:NSMakeRange(classNameOffset, 50)];
        NSString * className = NSSTRING(buffer);
        free(buffer);
        
        NSArray *crashAdress = [NSArray arrayWithContentsOfFile:crashAddressPath];
        
        //遍历每个class的method (实例方法)
        if (methodListOffset < max) {
            
            unsigned int methodCount;
            NSRange methodRange = NSMakeRange(methodListOffset+4, 0);
            data = [WBBladesTool read_bytes:methodRange length:4 fromFile:fileData];
            [data getBytes:&methodCount length:4];
            for (int j = 0; j<methodCount; j++) {
                
                //获取方法名
                methodRange = NSMakeRange(methodListOffset+8 + 24 * j, 0);
                data = [WBBladesTool read_bytes:methodRange length:8 fromFile:fileData];
                
                unsigned long long methodNameOffset;
                [data getBytes:&methodNameOffset length:8];
                methodNameOffset = methodNameOffset - vm;
                
                //方法名最大150字节
                uint8_t * buffer = (uint8_t *)malloc(150 + 1); buffer[150] = '\0';
                
                if (methodNameOffset < max) {
                    
                    [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,150)];
                    NSString * methodName = NSSTRING(buffer);
                    
                    methodRange = NSMakeRange(methodListOffset+8 +16 + 24 * j, 0);
                    data = [WBBladesTool read_bytes:methodRange length:8 fromFile:fileData];
                    
                    unsigned long long tmp;
                    [data getBytes:&tmp length:8];
                    
                    [crashAdress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                        unsigned long long crash = [(NSString *)obj longLongValue];
                        if ([self scanFuncBinaryCode:crash begin:tmp vb:vm fileData:fileData]) {
                            NSLog(@"起始地址:0x%llx    崩溃地址:0x%llx \n -[%@ %@]",tmp,crash,className,methodName);
                            NSString *key = [NSString stringWithFormat:@"%lld",crash];
                            if (!crashSymbolRst[key] || [crashSymbolRst[key][@"begin"] longLongValue] < tmp) {
                                NSMutableDictionary *dic = @{@"begin":@(tmp),@"symbol":[NSString stringWithFormat:@"-[%@ %@]",className,methodName]}.mutableCopy;
                                [crashSymbolRst setObject:dic forKey:key];
                            }
                        }
                    }];
                }
                free(buffer);
            }
        }
        if (classMethodListOffset < max) {
            
            unsigned int methodCount;
            NSRange methodRange = NSMakeRange(classMethodListOffset+4, 0);
            data = [WBBladesTool read_bytes:methodRange length:4 fromFile:fileData];
            [data getBytes:&methodCount length:4];
            for (int j = 0; j<methodCount; j++) {
                
                //获取方法名
                methodRange = NSMakeRange(classMethodListOffset+8 + 24 * j, 0);
                data = [WBBladesTool read_bytes:methodRange length:8 fromFile:fileData];
                
                unsigned long long methodNameOffset;
                [data getBytes:&methodNameOffset length:8];
                methodNameOffset = methodNameOffset - vm;
                
                //方法名最大150字节
                uint8_t * buffer = (uint8_t *)malloc(150 + 1); buffer[150] = '\0';
                if (methodNameOffset < max) {
                    
                    [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,150)];
                    NSString * methodName = NSSTRING(buffer);
                    
                    methodRange = NSMakeRange(classMethodListOffset+8 +16 + 24 * j, 0);
                    data = [WBBladesTool read_bytes:methodRange length:8 fromFile:fileData];
                    
                    unsigned long long tmp;
                    [data getBytes:&tmp length:8];
                    
                    [crashAdress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                        unsigned long long crash = [(NSString *)obj longLongValue];
                        if ([self scanFuncBinaryCode:crash begin:tmp vb:vm fileData:fileData] ) {
                            NSLog(@"起始地址:0x%llx    崩溃地址:0x%llx \n +[%@ %@]",tmp,crash,className,methodName);
                            NSString *key = [NSString stringWithFormat:@"%lld",crash];
                            if (!crashSymbolRst[key] || [crashSymbolRst[key][@"begin"] longLongValue] < tmp) {
                                NSMutableDictionary *dic = @{@"begin":@(tmp),@"symbol":[NSString stringWithFormat:@"+[%@ %@]",className,methodName]}.mutableCopy;
                                [crashSymbolRst setObject:dic forKey:key];
                            }
                        }
                    }];
                    
                    }
                    free(buffer);
                }
            }
        }
    }
    NSLog(@"%@",crashSymbolRst);
}


+ (BOOL)scanFuncBinaryCode:(unsigned long long)target  begin:(unsigned long long)begin  vb:(unsigned long long )vb fileData:(NSData*)fileData{
    
    if (begin > target + vb) {
        return NO;
    }
    
     unsigned int asmCode = 0;
    do {
        
        [fileData getBytes:&asmCode range:NSMakeRange(begin - vb, 4)];
        if (begin == target + vb) {
               return YES;
        }
           begin += 4;
    } while ((asmCode != 0xd65f03c0) && (asmCode != 0x14000001));
    return NO;
}

@end
