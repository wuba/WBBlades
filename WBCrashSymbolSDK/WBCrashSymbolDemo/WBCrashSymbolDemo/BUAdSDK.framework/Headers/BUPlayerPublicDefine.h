//
//  BUPlayerPublicDefine.h
//  BUAdSDK
//
//  Copyright © 2018年 bytedance. All rights reserved.
//

#ifndef BUPlayerPublicDefine_h
#define BUPlayerPublicDefine_h

typedef NS_ENUM(NSInteger, BUPlayerPlayState) {
    BUPlayerStateFailed    = 0,
    BUPlayerStateBuffering = 1,
    BUPlayerStatePlaying   = 2,
    BUPlayerStateStopped   = 3,
    BUPlayerStatePause     = 4,
    BUPlayerStateDefalt    = 5
};

@class BUPlayer;

@protocol BUPlayerDelegate <NSObject>

@optional
/**
 This method is called when the player status changes.
 */
- (void)player:(BUPlayer *)player stateDidChanged:(BUPlayerPlayState)playerState;
/**
 This method is called when the player is ready.
 */
- (void)playerReadyToPlay:(BUPlayer *)player;
/**
 This method is called when the player plays completion or occurrs error.
 */
- (void)playerDidPlayFinish:(BUPlayer *)player error:(NSError *)error;

/**
 This method is called when the player is clicked.
 */
- (void)player:(BUPlayer *)player recognizeTapGesture:(UITapGestureRecognizer *)gesture;


/**
 This method is called when the view is clicked during ad play.
 */
- (void)playerTouchesBegan:(BUPlayer *)player;

@end

#endif /* BUPlayerPublicDefine_h */
