//
//  WBCrashSymbol.h
//  WBCrashSymbol
//
//  Created by 邓竹立 on 2020/1/8.
//  Copyright © 2020 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WBCrashSymbol : NSObject


//日志解析
+ (void)trySymbolizeLog;

//展示日志
+ (void)showLog;

//清除日志
+ (void)clearCallStackSymbols;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
    
//保存二进制文件路径
void WBCrashSymbolStoreMachOPath(int argc, char * argv[]);
    
#ifdef __cplusplus
    }
#endif //__cplusplus
        
        
        @end
