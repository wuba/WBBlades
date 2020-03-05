//
//  BUAdSDKDefines.h
//  BUAdSDK
//
//  Copyright © 2017年 bytedance. All rights reserved.
//

#ifndef BUAdSDK_DEFINES_h
#define BUAdSDK_DEFINES_h

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, BUOfflineType) {
    BUOfflineTypeNone,  // Do not set offline
    BUOfflineTypeProtocol, // Offline dependence NSURLProtcol
    BUOfflineTypeWebview, // Offline dependence WKWebview
};

typedef NS_ENUM(NSInteger, BUAdSDKLogLevel) {
    BUAdSDKLogLevelNone,
    BUAdSDKLogLevelError,
    BUAdSDKLogLevelDebug
};

typedef NS_ENUM(NSInteger, BURitSceneType) {
    BURitSceneType_custom                  = 0,//custom
    BURitSceneType_home_open_bonus         = 1,//Login/open rewards (login, sign-in, offline rewards doubling, etc.)
    BURitSceneType_home_svip_bonus         = 2,//Special privileges (VIP privileges, daily rewards, etc.)
    BURitSceneType_home_get_props          = 3,//Watch rewarded video ad to gain skin, props, levels, skills, etc
    BURitSceneType_home_try_props          = 4,//Watch rewarded video ad to try out skins, props, levels, skills, etc
    BURitSceneType_home_get_bonus          = 5,//Watch rewarded video ad to get gold COINS, diamonds, etc
    BURitSceneType_home_gift_bonus         = 6,//Sweepstakes, turntables, gift boxes, etc
    BURitSceneType_game_start_bonus        = 7,//Before the opening to obtain physical strength, opening to strengthen, opening buff, task props
    BURitSceneType_game_reduce_waiting     = 8,//Reduce wait and cooldown on skill CD, building CD, quest CD, etc
    BURitSceneType_game_more_opportunities = 9,//More chances (resurrect death, extra game time, decrypt tips, etc.)
    BURitSceneType_game_finish_rewards     = 10,//Settlement multiple times/extra bonus (completion of chapter, victory over boss, first place, etc.)
    BURitSceneType_game_gift_bonus         = 11//The game dropped treasure box, treasures and so on
};

@protocol BUToDictionary <NSObject>
- (NSDictionary *)dictionaryValue;
@end

#endif
