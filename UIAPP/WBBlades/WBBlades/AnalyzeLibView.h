//
//  AnalyzeLibView.h
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

@class AnalyzeLibView;
@protocol AnalyzeLibViewProtocol <NSObject>

@required
-(void)analyzeLibView:(AnalyzeLibView *)view;

@end

@interface AnalyzeLibView : NSView

@property (nonatomic, weak) id <AnalyzeLibViewProtocol>delegate;

@property (nonatomic, copy) NSString *type;

@end

NS_ASSUME_NONNULL_END
