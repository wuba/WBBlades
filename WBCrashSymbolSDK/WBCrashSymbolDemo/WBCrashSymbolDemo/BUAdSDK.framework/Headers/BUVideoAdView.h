//
//  BUVideoAdView.h
//  BUAdSDK
//
//  Copyright © 2017年 bytedance. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "BUPlayerPublicDefine.h"
#import "BUMaterialMeta.h"

@class BUMaterialMeta;

NS_ASSUME_NONNULL_BEGIN

/**
 Control TikTok Audience Network video player.
 */
@protocol BUVideoEngine <NSObject>

/**
 Get the already played time.
 */
- (CGFloat)currentPlayTime;

/**
 Set video play when you support CustomMode
 **/
- (void)play;

/**
 Set video pause when you support CustomMode
**/
- (void)pause;

@end

@protocol BUVideoAdViewDelegate;


@interface BUVideoAdView : UIView<BUPlayerDelegate, BUVideoEngine>

@property (nonatomic, weak, nullable) id<BUVideoAdViewDelegate> delegate;
/**
required. Root view controller for handling ad actions.
 **/
@property (nonatomic, weak, readwrite) UIViewController *rootViewController;

/**
 Whether to allow pausing the video by clicking, default NO. Only for draw video(vertical video ads).
 **/
@property (nonatomic, assign) BOOL drawVideoClickEnable;

/**
 material information.
 */
@property (nonatomic, strong, readwrite, nullable) BUMaterialMeta *materialMeta;

/**
 Set your Video autoPlayMode when you support CustomMode
 if support CustomMode , default autoplay Video
 **/
@property (nonatomic, assign) BOOL supportAutoPlay;


- (instancetype)initWithMaterial:(BUMaterialMeta *)materialMeta;

/**
 Resume to the corresponding time.
 */
- (void)playerSeekToTime:(CGFloat)time;

/**
 Support configuration for pause button.
 @param playImg : the image of the button
 @param playSize : the size of the button. Set as cgsizezero to use default icon size.
 */
- (void)playerPlayIncon:(UIImage *)playImg playInconSize:(CGSize)playSize;

@end

@protocol BUVideoAdViewDelegate <NSObject>

@optional

/**
 This method is called when videoadview failed to play.
 @param error : the reason of error
 */
- (void)videoAdView:(BUVideoAdView *)videoAdView didLoadFailWithError:(NSError *_Nullable)error;

/**
 This method is called when videoadview playback status changed.
 @param playerState : player state after changed
 */
- (void)videoAdView:(BUVideoAdView *)videoAdView stateDidChanged:(BUPlayerPlayState)playerState;

/**
 This method is called when videoadview end of play.
 */
- (void)playerDidPlayFinish:(BUVideoAdView *)videoAdView;

/**
 This method is called when videoadview is clicked.
 */
- (void)videoAdViewDidClick:(BUVideoAdView *)videoAdView;

/**
 This method is called when videoadview's finish view is clicked.
 */
- (void)videoAdViewFinishViewDidClick:(BUVideoAdView *)videoAdView;

/**
 This method is called when another controller has been closed.
 @param interactionType : open appstore in app or open the webpage or view video ad details page.
 */
- (void)videoAdViewDidCloseOtherController:(BUVideoAdView *)videoAdView interactionType:(BUInteractionType)interactionType;

@end

NS_ASSUME_NONNULL_END
