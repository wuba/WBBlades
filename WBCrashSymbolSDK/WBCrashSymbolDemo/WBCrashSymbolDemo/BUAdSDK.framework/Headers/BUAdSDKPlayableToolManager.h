//
//  BUAdSDKPlayableToolManager.h
//  BUAdSDK
//
//  Copyright © 2019 bytedance. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BUAdSDKPlayableToolManager : NSObject

+ (instancetype)sharedInstance;

+ (void)setPlayableURL:(NSString *)url;

+ (void)setDownloadUrl:(NSString *)url;

+ (void)setDeeplinkUrl:(NSString *)url;

+ (void)setIsLandScape:(BOOL)isLandScape;

+ (void)clearAll;

@end

