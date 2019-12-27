//
//  LibAnalyzeWindowController.m
//  WBBlades
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
    
    // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    AnalyzeViewController *curVC = [[AnalyzeViewController alloc]initWithNibName:@"AnalyzeViewController" bundle:[NSBundle mainBundle]];;
    curVC.type = self.type;
    [self.window setContentViewController:curVC];
    [self showWindow:nil];

}
@end
