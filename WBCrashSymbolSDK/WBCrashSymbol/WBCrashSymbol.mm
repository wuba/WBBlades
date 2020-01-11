//
//  WBCrashSymbol.m
//  WBCrashSymbol
//
//  Created by 邓竹立 on 2020/1/8.
//  Copyright © 2020 邓竹立. All rights reserved.
//

#import "WBCrashSymbol.h"
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#import <mach-o/ldsyms.h>
#import "WBBladesTool.h"
#import "WBBladesDefines.h"
#import <UIKit/UIKit.h>


@implementation WBCrashSymbol

//用于保存SDK外，其他代码对异常拦截的函数指针
static NSUncaughtExceptionHandler *otherUncaughtExceptionHandler;

//进行exception 拦截
static void bladesCrashSymbolExceptionHandler (NSException *exception) {
    
    //如果有其他代码对异常进行拦截则先让他人进行异常处理
    if (otherUncaughtExceptionHandler && otherUncaughtExceptionHandler != &bladesCrashSymbolExceptionHandler) {
        otherUncaughtExceptionHandler(exception);
    }
    
    //获取调用栈和reason，并保存到磁盘
    NSArray *callStackSymbols = exception.callStackSymbols;
    NSMutableArray * callStackWithReason = [NSMutableArray arrayWithArray:callStackSymbols];
    [callStackWithReason insertObject:exception.reason atIndex:0];
    [callStackWithReason writeToFile:[WBCrashSymbol crashCallStackPath] atomically:YES];
}

//同理，用于保存SDK外，其他代码对signal拦截的函数指针
static void (*otherSignalHandler)(int a, struct __siginfo * b,void * c);

//进行signal 拦截
static void bladesCrashSymbolSignalHandler (int sig, struct __siginfo *info,void * c) {
    //如果有其他代码对signal进行拦截则先让他人进行异常处理
    if (otherSignalHandler && otherSignalHandler != &bladesCrashSymbolSignalHandler) {
        otherSignalHandler(sig,info,c);
    }
    
    //将当前线程堆栈写入文件
    NSArray *callStackSymbols = [NSThread callStackSymbols];
    [callStackSymbols writeToFile:[WBCrashSymbol crashCallStackPath] atomically:YES];
}

+ (void)load{
    //设置exception 拦截
    otherUncaughtExceptionHandler = NSGetUncaughtExceptionHandler();
    NSSetUncaughtExceptionHandler(bladesCrashSymbolExceptionHandler);
    
    //设置signal拦截，此处只拦截了SIGSEGV
    struct sigaction newact,oldact;
    newact.sa_flags = SA_SIGINFO;
    newact.__sigaction_u.__sa_sigaction = bladesCrashSymbolSignalHandler;
    sigaction(SIGSEGV, &newact, &oldact);
    otherSignalHandler = oldact.__sigaction_u.__sa_sigaction;
}

//用于保存可执行文件的路径
static NSString *fileDataPath;

extern "C" {
    
    //保存可执行文件的路径
    void WBCrashSymbolStoreMachOPath(int argc, char * argv[]){
        fileDataPath = [NSString stringWithFormat:@"%s",argv[0]];
    }
}


//展示log
+ (void)showLog{
    //读取日志
    NSArray *callStackSymbols = [NSArray arrayWithContentsOfFile:[self crashCallStackPath]];
    UITextView *callStackView = [[UITextView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    [keyWindow addSubview:callStackView];
    for (NSInteger i = 0; i < callStackSymbols.count; i++) {
        callStackView.text = [NSString stringWithFormat:@"%@ \n %@",callStackView.text,callStackSymbols[i]];
    }
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(hiddenDebugShowView:)];
    [callStackView addGestureRecognizer:tap];
}

+ (void)trySymbolizeLog{
    
    //读取日志
    NSArray *callStackSymbols = [NSArray arrayWithContentsOfFile:[self crashCallStackPath]];
    UITextView *callStackView = [[UITextView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    [keyWindow addSubview:callStackView];
    for (NSInteger i = 0; i < callStackSymbols.count; i++) {
        callStackView.text = [NSString stringWithFormat:@"%@ \n %@",callStackView.text,callStackSymbols[i]];
    }
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(hiddenDebugShowView:)];
    [callStackView addGestureRecognizer:tap];
    if (!callStackSymbols) {
        return;
    }
    NSString *crashAddress = @"";
    if (!fileDataPath) {
        return;
    }
    
    //读取二进制文件
    NSData *fileData = [self readMachOFile:fileDataPath];
    
    //获取二进制文件名
    NSString *fileName = [fileDataPath lastPathComponent]?:@"58tongcheng";
    
    //遍历堆栈，提取相关崩溃地址
    for (NSInteger i = 0; i < callStackSymbols.count ; i++) {
        NSString *callStack = callStackSymbols[i];
        if ([callStack containsString:fileName]) {
            NSString *offset = [[callStack componentsSeparatedByString:@"+"] lastObject];
            offset = [offset stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (offset.length > 0) {
                if (i < callStackSymbols.count - 1) {
                    crashAddress = [crashAddress stringByAppendingString:@","];
                }
                crashAddress = [crashAddress stringByAppendingString:offset];
            }
        }
    }
    
    //扫描二进制文件，根据崩溃偏移地址获取符号
    NSDictionary *result = [self scanAllClassMethodList:fileData crashOffsets:crashAddress];
    
    callStackView.text = [NSString stringWithFormat:@"%@\n \n解析后 \n \n",callStackView.text];
    
    //符号化展示
    for (NSInteger i = 0; i < callStackSymbols.count; i++) {
        NSString *callStack = callStackSymbols[i];
        if ([callStack containsString:fileName]) {
            NSString *relAddress = [[callStack componentsSeparatedByString:@"+"] firstObject];
            NSString *offset = [[callStack componentsSeparatedByString:@"+"] lastObject];
            offset = [offset stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (offset.length > 0) {
                NSString *symbol = result[offset][@"symbol"];
                if (symbol) {
                    NSString *addressSymbol = [relAddress stringByAppendingString:symbol];
                    callStackView.text = [NSString stringWithFormat:@"%@ \n %@",callStackView.text,addressSymbol];
                    continue;
                }
            }
        }
        callStackView.text = [NSString stringWithFormat:@"%@ \n %@",callStackView.text,callStackSymbols[i]];
    }
}

+ (void)hiddenDebugShowView:(UITapGestureRecognizer *)tap{
    [tap.view removeFromSuperview];
}

+ (void)clearCallStackSymbols{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error;
    [fileManager removeItemAtPath:[self crashCallStackPath] error:&error];
    
    if (error) {
        NSLog(@"清除失败");
    }
}

//扫描二进制
+ (NSDictionary *)scanAllClassMethodList:(NSData *)fileData crashOffsets:(NSString *)crashAddresses{
    
    unsigned long long max = [fileData length];
    
    //获取header信息
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    //classlist
    section_64 classList = {0};
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    
    //遍历load commands
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
                        
                        //记录classlist
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
    
    NSMutableDictionary *crashSymbolRst = @{}.mutableCopy;
    //获取所有类classlist
    NSRange range = NSMakeRange(classList.offset, 0);
    for (int i = 0; i < classList.size / 8 ; i++) {
        
        //类地址
        unsigned long long classAddress;
        NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
        [data getBytes:&classAddress range:NSMakeRange(0, 8)];
        unsigned long long classOffset = classAddress - vm;
        
        //类结构体
        class64 targetClass = {0};
        NSRange targetClassRange = NSMakeRange(classOffset, 0);
        data = [WBBladesTool readBytes:targetClassRange length:sizeof(class64) fromFile:fileData];
        [data getBytes:&targetClass length:sizeof(class64)];
        
        //详细结构体
        class64Info targetClassInfo = {0};
        unsigned long long targetClassInfoOffset = targetClass.data - vm;
        targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
        NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
        data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
        [data getBytes:&targetClassInfo length:sizeof(class64Info)];
        unsigned long long classNameOffset = targetClassInfo.name - vm;
        
        //元类
        class64 metaClass = {0};
        NSRange metaClassRange = NSMakeRange(targetClass.isa - vm, 0);
        data = [WBBladesTool readBytes:metaClassRange length:sizeof(class64) fromFile:fileData];
        [data getBytes:&metaClass length:sizeof(class64)];
        
        //元类详细结构体
        class64Info metaClassInfo = {0};
        unsigned long long metaClassInfoOffset = metaClass.data - vm;
        metaClassInfoOffset = (metaClassInfoOffset / 8) * 8;
        NSRange metaClassInfoRange = NSMakeRange(metaClassInfoOffset, 0);
        data = [WBBladesTool readBytes:metaClassInfoRange length:sizeof(class64Info) fromFile:fileData];
        [data getBytes:&metaClassInfo length:sizeof(class64Info)];
        
        unsigned long long methodListOffset = targetClassInfo.baseMethods - vm;
        unsigned long long classMethodListOffset = metaClassInfo.baseMethods - vm;
        
        //类名最大50字节
        uint8_t * buffer = (uint8_t *)malloc(50 + 1); buffer[50] = '\0';
        [fileData getBytes:buffer range:NSMakeRange(classNameOffset, 50)];
        NSString * className = NSSTRING(buffer);
        free(buffer);
        
        NSArray *crashAddress = [crashAddresses componentsSeparatedByString:@","];
        
        //遍历每个class的method (实例方法)
        if (methodListOffset > 0 && methodListOffset < max) {
            
            unsigned int methodCount;
            NSRange methodRange = NSMakeRange(methodListOffset+4, 0);
            data = [WBBladesTool readBytes:methodRange length:4 fromFile:fileData];
            [data getBytes:&methodCount length:4];
            for (int j = 0; j<methodCount; j++) {
                
                //获取方法名
                methodRange = NSMakeRange(methodListOffset+8 + 24 * j, 0);
                data = [WBBladesTool readBytes:methodRange length:8 fromFile:fileData];
                
                unsigned long long methodNameOffset;
                [data getBytes:&methodNameOffset length:8];
                methodNameOffset = methodNameOffset - vm;
                
                //方法名最大150字节
                uint8_t * buffer = (uint8_t *)malloc(150 + 1); buffer[150] = '\0';
                
                if (methodNameOffset > 0 && methodNameOffset < max) {
                    
                    //获取方法名
                    [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,150)];
                    NSString * methodName = NSSTRING(buffer);
                    
                    //获取IMP
                    methodRange = NSMakeRange(methodListOffset+8 +16 + 24 * j, 0);
                    data = [WBBladesTool readBytes:methodRange length:8 fromFile:fileData];
                    
                    unsigned long long tmp;
                    [data getBytes:&tmp length:8];
                    NSLog(@"遍历 -[%@ %@]",className,methodName);
                    
                    [crashAddress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                        unsigned long long crash = [(NSString *)obj longLongValue];
                        
                        //查找该函数指令区间范围内是否有崩溃地址
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
        if (classMethodListOffset > 0 && classMethodListOffset < max) {
            
            unsigned int methodCount;
            NSRange methodRange = NSMakeRange(classMethodListOffset+4, 0);
            data = [WBBladesTool readBytes:methodRange length:4 fromFile:fileData];
            [data getBytes:&methodCount length:4];
            for (int j = 0; j<methodCount; j++) {
                
                //获取方法名
                methodRange = NSMakeRange(classMethodListOffset+8 + 24 * j, 0);
                data = [WBBladesTool readBytes:methodRange length:8 fromFile:fileData];
                
                unsigned long long methodNameOffset;
                [data getBytes:&methodNameOffset length:8];
                methodNameOffset = methodNameOffset - vm;
                
                //方法名最大150字节
                uint8_t * buffer = (uint8_t *)malloc(150 + 1); buffer[150] = '\0';
                if (methodNameOffset > 0 && methodNameOffset < max) {
                    
                    [fileData getBytes:buffer range:NSMakeRange(methodNameOffset,150)];
                    NSString * methodName = NSSTRING(buffer);
                    
                    methodRange = NSMakeRange(classMethodListOffset+8 +16 + 24 * j, 0);
                    data = [WBBladesTool readBytes:methodRange length:8 fromFile:fileData];
                    
                    unsigned long long tmp;
                    [data getBytes:&tmp length:8];
                    
                    NSLog(@"遍历 +[%@ %@]",className,methodName);
                    [crashAddress enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                        unsigned long long crash = [(NSString *)obj longLongValue];
                        
                        //查找该函数指令区间范围内是否有崩溃地址
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

    return crashSymbolRst;
}

static void * BladesMemdup( void *mem, unsigned long long len){
    void *dup = malloc(len);
    memcpy(dup, mem, len);
    return dup;
}

+ (NSData *)readMachOFile:(NSString *)path{

    //获取磁盘中的Mach-O
    NSData *fileData = [NSData dataWithContentsOfFile:path];
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    
    //文件是否加密
    unsigned int cryptID = 0;
    unsigned long long currentLcLocation = sizeof(mach_header_64);
    NSRange segmentTextRange = {0};
    NSRange segmentRoDataRange = {0};
    
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command* cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];
        
        if (cmd->cmd == LC_ENCRYPTION_INFO) {
            
            //查找加密位
            encryption_info_command segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(encryption_info_command))];
            cryptID = segmentCommand.cryptid;
            
        }else if (cmd->cmd == LC_SEGMENT_64) {
            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];
            
            //记录TEXT和RODATA 只读段位置
            if ([segName isEqualToString:SEGMENT_TEXT]) {
                segmentTextRange = NSMakeRange(segmentCommand.fileoff, segmentCommand.filesize);
            }else if ([segName isEqualToString:SEGMENT_RODATA]){
                segmentRoDataRange = NSMakeRange(segmentCommand.fileoff, segmentCommand.filesize);
            }
        }
        
        currentLcLocation += cmd->cmdsize;
        free(cmd);
    }
    
    //如果是未加密的包，则直接返回二进制
    if (cryptID == 0) {
        return fileData;
    }
    
    //正式包或者TestFlight包需要砸壳
    uintptr_t textP = ((uintptr_t)&_mh_execute_header) + segmentTextRange.location;
    void *text = BladesMemdup((void *)textP,segmentTextRange.length);
    
    uintptr_t roDataP = ((uintptr_t)&_mh_execute_header) + segmentRoDataRange.location;
    void *roData = BladesMemdup((void *)roDataP,segmentRoDataRange.length);
    
    NSMutableData *tmp = [NSMutableData dataWithData:fileData];
    [tmp replaceBytesInRange:segmentTextRange withBytes:text];
    [tmp replaceBytesInRange:segmentRoDataRange withBytes:roData];
    fileData = [tmp copy];
    
//
//    NSString * documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
//    documentPath = [documentPath stringByAppendingPathComponent:@"bin"];
//    documentPath = [documentPath stringByAppendingPathExtension:@"copy"];
//    [fileData writeToFile:documentPath atomically:YES];
////
    return fileData;
}


//扫描汇编
+ (BOOL)scanFuncBinaryCode:(unsigned long long)target  begin:(unsigned long long)begin  vb:(unsigned long long )vb fileData:(NSData*)fileData{
    
    if (begin > target + vb) {
        return NO;
    }
    
    //arm64 汇编代码4字节
    unsigned int asmCode = 0;
    do {
        //获取汇编代码
        [fileData getBytes:&asmCode range:NSMakeRange(begin - vb, 4)];
        if (begin == target + vb) {
            return YES;
        }
        begin += 4;
    } while (asmCode != RET);
    return NO;
}

+ (NSString *)crashCallStackPath{
    NSString * documentPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    documentPath = [documentPath stringByAppendingPathComponent:@"crash"];
    documentPath = [documentPath stringByAppendingPathExtension:@"ips"];
    return documentPath;
}

@end


