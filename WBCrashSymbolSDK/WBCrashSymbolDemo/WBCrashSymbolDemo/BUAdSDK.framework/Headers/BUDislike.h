//
//  BUDislike.h
//  BUAdSDK
//
//  Copyright © 2018年 bytedance. All rights reserved.
//

#import <Foundation/Foundation.h>
@class BUNativeAd;
@class BUDislikeWords;

/**
 !!! important :
 Please report to the sdk the user’s selection, inaccurate model will result in poor ad performance.
 */
@interface BUDislike : NSObject
/**
 The array of BUDislikeWords which have reasons for dislike.
 The application can show the secondary page for dislike if '[filterWords.options count] > 0'.
 */
@property (nonatomic, copy, readonly) NSArray<BUDislikeWords *> *filterWords;

/**
 Initialize with nativeAd to get filterWords.
 return BUDislike
 */
- (instancetype)initWithNativeAd:(BUNativeAd *)nativeAd;

/**
 Call this method after the user chose dislike reasons.
 (Only for object which uses 'BUDislike.filterWords')
 @param filterWord : reasons for dislike
 @note : don't need to call this method if '[filterWords.options count] > 0'.
 @note :please dont't change 'BUDislike.filterWords'.
        'filterWord' must be one of 'BUDislike.filterWords', otherwise it will be filtered.
 */
- (void)didSelectedFilterWordWithReason:(BUDislikeWords *)filterWord;

@end

