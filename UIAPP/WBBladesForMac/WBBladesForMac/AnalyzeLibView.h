//
//  AnalyzeLibView.h
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "AnalyzeHeader.h"

NS_ASSUME_NONNULL_BEGIN

@interface AnalyzeLibView : NSView

/**
 *  根据Type来初始化View
 */
- (instancetype)initWithFrame:(NSRect)frameRect type:(AnalyzeType)type;

/**
 *  结束
 */
- (void)closeWindow:(NSWindow *)window;

@end

NS_ASSUME_NONNULL_END
