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

@interface AnalyzeViewController ()

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
        if ([self.types isEqualToString:@"1"]) {
            _controlView = [[AnalyzeLibView alloc]initWithFrame:self.view.frame];
        }else if([self.types isEqualToString:@"2"]){
            
        }else{
            _controlView = [[AnalyzeCrashView alloc]initWithFrame:self.view.frame];
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
    if ([self.controlView respondsToSelector:@selector(stopAnalyze)]) {
        [self.controlView performSelector:@selector(stopAnalyze)];
    }
    [self.view.window orderOut:nil];
}
@end
