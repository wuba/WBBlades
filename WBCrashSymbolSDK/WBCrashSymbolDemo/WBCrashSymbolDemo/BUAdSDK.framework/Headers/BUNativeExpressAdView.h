//
//  BUNativeExpressAdView.h
//  BUAdSDK
//
//  Created by bytedance on 2019/1/20.
//  Copyright © 2019年 bytedance. All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface BUNativeExpressAdView : UIView
/**
 * Whether render is ready
 */
@property (nonatomic, assign, readonly) BOOL isReady;

/// media configuration parameters.
@property (nonatomic, copy, readonly) NSDictionary *mediaExt;

/*
 required.
 Root view controller for handling ad actions.
 */
@property (nonatomic, weak) UIViewController *rootViewController;

/**
 required
 */
- (void)render;
@end

NS_ASSUME_NONNULL_END
