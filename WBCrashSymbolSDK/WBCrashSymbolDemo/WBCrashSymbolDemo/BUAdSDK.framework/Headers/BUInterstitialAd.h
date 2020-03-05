//
//  BUInterstitialAd.h
//  BUAdSDK
//
//  Copyright © 2017年 bytedance. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "BUAdSDKDefines.h"
#import "BUMaterialMeta.h"

NS_ASSUME_NONNULL_BEGIN

@class BUSize;
@protocol BUInterstitialAdDelegate;

@interface BUInterstitialAd : NSObject
@property (nonatomic, weak, nullable) id<BUInterstitialAdDelegate> delegate;
@property (nonatomic, getter=isAdValid, readonly) BOOL adValid;

/// media configuration parameters.
@property (nonatomic, copy, readonly) NSDictionary *mediaExt;

/**
 Initializes interstitial ad.
 @param slotID : The unique identifier of interstitial ad.
 @param expectSize : custom size, default 600px * 400px
 @return BUInterstitialAd
 */
- (instancetype)initWithSlotID:(NSString *)slotID size:(BUSize *)expectSize NS_DESIGNATED_INITIALIZER;
/**
 Load interstitial ad datas.
 */
- (void)loadAdData;
/**
 Display interstitial ad.
 @param rootViewController : root view controller for displaying ad.
 @return : whether it is successfully displayed.
 */
- (BOOL)showAdFromRootViewController:(UIViewController *)rootViewController;

@end

@protocol BUInterstitialAdDelegate <NSObject>

@optional
/**
 This method is called when interstitial ad material loaded successfully.
 */
- (void)interstitialAdDidLoad:(BUInterstitialAd *)interstitialAd;

/**
 This method is called when interstitial ad material failed to load.
 @param error : the reason of error
 */
- (void)interstitialAd:(BUInterstitialAd *)interstitialAd didFailWithError:(NSError * _Nullable)error;

/**
 This method is called when interstitial ad slot will be showing.
 */
- (void)interstitialAdWillVisible:(BUInterstitialAd *)interstitialAd;

/**
 This method is called when interstitial ad is clicked.
 */
- (void)interstitialAdDidClick:(BUInterstitialAd *)interstitialAd;

/**
 This method is called when interstitial ad is about to close.
 */
- (void)interstitialAdWillClose:(BUInterstitialAd *)interstitialAd;

/**
 This method is called when interstitial ad is closed.
 */
- (void)interstitialAdDidClose:(BUInterstitialAd *)interstitialAd;

/**
 This method is called when another controller has been closed.
 @param interactionType : open appstore in app or open the webpage or view video ad details page.
 */
- (void)interstitialAdDidCloseOtherController:(BUInterstitialAd *)interstitialAd interactionType:(BUInteractionType)interactionType;
@end

NS_ASSUME_NONNULL_END
