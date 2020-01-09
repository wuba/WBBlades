//
//  ViewController.m
//  WBCrashSymbolDemo
//
//  Created by 邓竹立 on 2020/1/8.
//  Copyright © 2020 邓竹立. All rights reserved.
//

#import "ViewController.h"
#import "WBCrashSymbol.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.view.backgroundColor = [UIColor whiteColor];
}

- (IBAction)makeCrash:(id)sender {
    NSArray *array = @[];
    NSLog(@"%@",array[3]);
}
- (IBAction)showLog:(id)sender {
    [WBCrashSymbol showLog];
}
- (IBAction)symbolize:(id)sender {
    [WBCrashSymbol trySymbolizeLog];
}
- (IBAction)clearLog:(id)sender {
    [WBCrashSymbol clearCallStackSymbols];
}

@end
