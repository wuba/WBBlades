//
//  ViewController.m
//  WBBladesForMac
//
//  Created by 邓竹立 on 2019/12/19.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "MainViewController.h"
#import "AnalyzeWindowController.h"
#import "AnalyzeHeader.h"

@interface MainViewController ()

@property(nonatomic,strong)IBOutlet NSButton *staticLibBtn;
@property(nonatomic,strong)IBOutlet NSButton *unusedClassBtn;
@property(nonatomic,strong)IBOutlet NSButton *crashAnalyzeBtn;

@property(nonatomic,strong)NSTask *bladesTask;

@end

@implementation MainViewController

- (void)viewDidLoad {
    [super viewDidLoad];

//    [self startTask];
}

//静态库大小分析
- (IBAction)staticLibSizeClicked:(id)sender {
    NSLog(@"static");
    [self createANewWindow:AnalyzeStaticLibrarySizeType];
}

//无用类分析
- (IBAction)unusedClassClicked:(id)sender {
    NSLog(@"unused");
   [self createANewWindow:AnalyzeAppUnusedClassType];
}

//无符号崩溃日志分析
- (IBAction)crashAnalyzeClicked:(id)sender {
    NSLog(@"crash");
    [self createANewWindow:AnalyzeAppCrashLogType];
}

//为了同时可以进行多个任务，每个功能都新建一个Window
- (void)createANewWindow:(AnalyzeType)type{
    AnalyzeWindowController *wc = [[AnalyzeWindowController alloc]initWithWindowNibName:@"AnalyzeWindowController"];
    wc.type = type;
    [wc.window center];
    [wc.window orderFront:nil];
}
@end
