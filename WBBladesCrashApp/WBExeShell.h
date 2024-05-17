//
//  WBExeShell.h
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2024/5/15.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBExeShell : NSObject
+ (NSString *)crashAnalysisLogContent:(NSString *)logContent dSYMPath:(NSString *)dSYMPath ProcessName:(NSString *)proName;
@end

NS_ASSUME_NONNULL_END
