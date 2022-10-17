//
//  NSObject+WBBladesScanManager_AutoHook.h
//  WBBlades
//
// Created by 竹林七闲 on 2022/9/1.
//

#import <Foundation/Foundation.h>
#import "WBBladesScanManager.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (AutoHook)
+ (NSArray *)getAllOCClasses:(NSString *)fileData;
+ (void)endAutoHookProcess;
- (void)typeDescription ;
+ (NSString *)anonymousWithType:(id)structType;
@end

NS_ASSUME_NONNULL_END
