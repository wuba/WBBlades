//
//  AnalyzeViewController.m
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeViewController.h"
#import "AnalyzeCrashView.h"
#import "AnalyzeLibView.h"

@interface AnalyzeViewController () <AnalyzeLibViewProtocol,AnalyzeCrashViewProtocol>

@property (nonatomic,strong) NSView *controlView;

@end

@implementation AnalyzeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do view setup here.
    
    [self.view addSubview:self.controlView];
}

-(NSView *)controlView{
    if (!_controlView) {
        if ([self.types isEqualToString:@"3"]) {
            _controlView = [[AnalyzeCrashView alloc]initWithFrame:self.view.frame];
            AnalyzeCrashView *crashView = (AnalyzeCrashView *)_controlView;
            crashView.delegate = self;
        }else{
            _controlView = [[AnalyzeLibView alloc]initWithFrame:self.view.frame];
            AnalyzeLibView *libView = (AnalyzeLibView *)_controlView;
            libView.type = self.types;
            libView.delegate = self;
        }
    }
    return _controlView;
}

- (void)viewDidLayout{
    [super viewDidLayout];
    NSButton *closeButton = [self.view.window standardWindowButton:NSWindowCloseButton];
    [closeButton setTarget:self];
    [closeButton setAction:@selector(closeCurWindow)];
}

- (void)closeCurWindow{
    [self.view.window orderOut:nil];
    NSLog(@"close");
}

#pragma mark AnalyzeLibViewProtocol
- (void)analyzeLibView:(AnalyzeLibView *)view{
    
}

#pragma mark AnalyzeCrashViewProtocol
- (void)analyzeCrashView:(AnalyzeCrashView *)view{
    
}
@end
