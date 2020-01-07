//
//  AnalyzeCrashView.h
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@class AnalyzeCrashView;
@protocol AnalyzeCrashViewProtocol <NSObject>

@required
-(void)analyzeCrashView:(AnalyzeCrashView *)view;

@end

@interface AnalyzeCrashView : NSView

@property (nonatomic, weak) id <AnalyzeCrashViewProtocol>delegate;

@end

NS_ASSUME_NONNULL_END
