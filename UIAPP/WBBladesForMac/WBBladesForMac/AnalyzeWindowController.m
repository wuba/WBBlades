//
//  LibAnalyzeWindowController.m
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeWindowController.h"
#import "AnalyzeViewController.h"

@interface AnalyzeWindowController ()

@end

@implementation AnalyzeWindowController

- (void)windowDidLoad {
    [super windowDidLoad];
    
    NSString *titles = @"";
    if (self.type == AnalyzeStaticLibrarySizeType) {
        titles = @"静态库体积分析";
    } else if (self.type == AnalyzeAppUnusedClassType) {
        titles = @"无用类检测工具";
    } else if (self.type == AnalyzeAppCrashLogType) {
        titles = @"无符号崩溃解析";
    }
    self.window.title = titles;
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    AnalyzeViewController *curVC = [[AnalyzeViewController alloc]initWithNibName:@"AnalyzeViewController" bundle:[NSBundle mainBundle]];
    curVC.type = self.type;
    [self.window setContentViewController:curVC];
    [self showWindow:nil];
}

@end
