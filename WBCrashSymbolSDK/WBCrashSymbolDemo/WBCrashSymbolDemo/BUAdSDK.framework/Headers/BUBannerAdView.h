//
//  BUBannerAdView.h
//  BUAdSDK
//
//  Copyright © 2017年 bytedance. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "BUNativeAd.h"

@class BUDislikeWords, BUAdSlot;
@protocol BUBannerAdViewDelegate;


NS_ASSUME_NONNULL_BEGIN

@interface BUBannerAdView : UIView

@property (nonatomic, weak, nullable) id<BUBannerAdViewDelegate> delegate;

/**
 The carousel interval, in seconds, is set in the range of 30~120s, and is passed during initialization. If it does not meet the requirements, it will not be in carousel ad.
 */
@property (nonatomic, assign, readonly) NSInteger interval;

/**
 The dislikeButton has been added to the upper right corner of the BannerView by default, it will respond to dislike reasons.
 */
@property (nonatomic, strong, readonly, nonnull) UIButton *dislikeButton;

/// media configuration parameters.
@property (nonatomic, copy, readonly) NSDictionary *mediaExt;

- (instancetype)initWithIdentifier:(NSString *)slotID
                rootViewController:(UIViewController *)rootViewController
                            adSize:(CGSize)adSize
                  withShowPosition:(BUAdSlotPosition)showPosition
             WithIsSupportDeepLink:(BOOL)isSupportDeepLink;

- (instancetype)initWithIdentifier:(NSString *)slotID
                rootViewController:(UIViewController *)rootViewController
                            adSize:(CGSize)adSize
                  withShowPosition:(BUAdSlotPosition)showPosition
             WithIsSupportDeepLink:(BOOL)isSupportDeepLink
                          interval:(NSInteger)interval;

- (instancetype)initWithSlotID:(NSString *)slotID
                          size:(BUSize *)adSize
            rootViewController:(UIViewController *)rootViewController;

- (instancetype)initWithSlotID:(NSString *)slotID
                          size:(BUSize *)adSize
            rootViewController:(UIViewController *)rootViewController
                      interval:(NSInteger)interval;

- (void)loadAdData;

- (IBAction)dislikeAction:(id)sender;
@end

@protocol BUBannerAdViewDelegate <NSObject>

@optional

/**
 This method is called when bannerAdView ad slot loaded successfully.
 @param bannerAdView : view for bannerAdView
 @param nativeAd : nativeAd for bannerAdView
 */
- (void)bannerAdViewDidLoad:(BUBannerAdView *)bannerAdView WithAdmodel:(BUNativeAd *_Nullable)nativeAd;

/**
 This method is called when bannerAdView ad slot failed to load.
 @param error : the reason of error
 */
- (void)bannerAdView:(BUBannerAdView *)bannerAdView didLoadFailWithError:(NSError *_Nullable)error;

/**
 This method is called when bannerAdView ad slot showed new ad.
 */
- (void)bannerAdViewDidBecomVisible:(BUBannerAdView *)bannerAdView WithAdmodel:(BUNativeAd *_Nullable)nativeAd;

/**
 This method is called when bannerAdView is clicked.
 */
- (void)bannerAdViewDidClick:(BUBannerAdView *)bannerAdView WithAdmodel:(BUNativeAd *_Nullable)nativeAd;

/**
 This method is called when the user clicked dislike button and chose dislike reasons.
 @param filterwords : the array of reasons for dislike.
 */
- (void)bannerAdView:(BUBannerAdView *)bannerAdView dislikeWithReason:(NSArray<BUDislikeWords *> *_Nullable)filterwords;

/**
 This method is called when another controller has been closed.
 @param interactionType : open appstore in app or open the webpage or view video ad details page.
 */
- (void)bannerAdViewDidCloseOtherController:(BUBannerAdView *)bannerAdView interactionType:(BUInteractionType)interactionType;

@end

NS_ASSUME_NONNULL_END

