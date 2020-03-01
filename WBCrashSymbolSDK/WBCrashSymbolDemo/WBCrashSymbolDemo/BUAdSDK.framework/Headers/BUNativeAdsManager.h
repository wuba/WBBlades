//
//  BUNativeAdsManager.h
//  BUAdSDK
//
//  Copyright © 2017 bytedance. All rights reserved.
//

/**
 BUNativeAdsManager : for multiple requests at the same time.
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "BUAdSlot.h"
#import "BUMaterialMeta.h"
#import "BUNativeAd.h"

@protocol BUNativeAdsManagerDelegate;

NS_ASSUME_NONNULL_BEGIN
/// Bunativeadsmanager class can request multiple ad data per time.
@interface BUNativeAdsManager : NSObject

@property (nonatomic, strong, nullable) BUAdSlot *adslot;
@property (nonatomic, strong, nullable) NSArray<BUNativeAd *> *data;
/// The delegate for receiving state change messages such as requests succeeding/failing.
/// The delegate can be set to any object which conforming to <BUNativeAdsManagerDelegate>.
@property (nonatomic, weak, nullable) id<BUNativeAdsManagerDelegate> delegate;

- (instancetype)initWithSlot:(BUAdSlot * _Nullable) slot;

/**
 It is recommended to request no more than 3 ads.
 The maximum is 10.
 */
- (void)loadAdDataWithCount:(NSInteger)count;

@end

@protocol BUNativeAdsManagerDelegate <NSObject>

@optional

- (void)nativeAdsManagerSuccessToLoad:(BUNativeAdsManager *)adsManager nativeAds:(NSArray<BUNativeAd *> *_Nullable)nativeAdDataArray;

- (void)nativeAdsManager:(BUNativeAdsManager *)adsManager didFailWithError:(NSError *_Nullable)error;

@end

NS_ASSUME_NONNULL_END
