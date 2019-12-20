//
//  ViewController.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/19.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "MainViewController.h"
#import "AnalyzeWindowController.h"

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

- (IBAction)staticLibSizeClicked:(id)sender {
    NSLog(@"static");
    [self createANewWindow:@"1"];
}

- (IBAction)unusedClassClicked:(id)sender {
    NSLog(@"unused");
   [self createANewWindow:@"2"];
}

- (IBAction)crashAnalyzeClicked:(id)sender {
    NSLog(@"crash");
    [self createANewWindow:@"3"];
}

- (void)createANewWindow:(NSString *)type{
    AnalyzeWindowController *wc = [[AnalyzeWindowController alloc]initWithWindowNibName:@"AnalyzeWindowController"];
    wc.types = type;
    [wc.window center];
    [wc.window orderFront:nil];
}

- (void)startTask{
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"WBBlades" ofType:@""];
    self.bladesTask = [[NSTask alloc] init];
    [self.bladesTask setLaunchPath:path];

    [self.bladesTask setArguments:[NSArray arrayWithObjects:@"1", @"/Users/a58/wb_frameworks/WBAPP3rdLib/wb3rdcomponent", nil]];
    [self.bladesTask launch];
    
    //同步执行
    [self.bladesTask waitUntilExit];
    NSLog(@"ok");
    
//    [self.bladesTask resume]; 恢复
//    [self.bladesTask terminate]; 终止
//    [self.bladesTask suspend]；挂起
}



@end
