//
//  AnalyzeLibView.h
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "AnalyzeHeader.h"

NS_ASSUME_NONNULL_BEGIN

@class AnalyzeLibView;
@protocol AnalyzeLibViewProtocol <NSObject>

@required
-(void)analyzeLibView:(AnalyzeLibView *)view;

@end

@interface AnalyzeLibView : NSView

@property (nonatomic, weak) id <AnalyzeLibViewProtocol>delegate;

-(instancetype)initWithFrame:(NSRect)frameRect type:(AnalyzeType)type;

-(void)stopAnalyze;

@end

NS_ASSUME_NONNULL_END
