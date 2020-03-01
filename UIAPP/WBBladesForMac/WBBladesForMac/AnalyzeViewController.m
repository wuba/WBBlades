//
//  AnalyzeViewController.m
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeViewController.h"
#import "AnalyzeCrashView.h"
#import "AnalyzeLibView.h"

@interface AnalyzeViewController ()

@property (nonatomic,strong) NSView *controlView;

@end

@implementation AnalyzeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    
    [self.view addSubview:self.controlView];
}

- (NSView *)controlView {
    if (!_controlView) {
        if (self.type == AnalyzeAppCrashLogType) {//崩溃日志
            _controlView = [[AnalyzeCrashView alloc]initWithFrame:self.view.frame];
        }else{
            _controlView = [[AnalyzeLibView alloc]initWithFrame:self.view.frame type:self.type];
        }
    }
    return _controlView;
}

- (void)viewDidLayout {
    [super viewDidLayout];
    NSButton *closeButton = [self.view.window standardWindowButton:NSWindowCloseButton];
    [closeButton setTarget:self];
    [closeButton setAction:@selector(closeCurWindow)];
}

- (void)closeCurWindow {
    if ([self.controlView respondsToSelector:@selector(closeWindow:)]) {
        [self.controlView performSelector:@selector(closeWindow:) withObject:self.view.window];
    }
}

@end
