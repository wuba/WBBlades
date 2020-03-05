//
//  ViewController.m
//  WBBladesDemoApp
//
//  Created by 邓竹立 on 2020/1/14.
//  Copyright © 2020 邓竹立. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    
    UIButton *button = [UIButton buttonWithType:UIButtonTypeCustom];
    [button setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
    button.frame = CGRectMake(100, 100, 200, 50);
    [button setTitle:@"制造崩溃" forState:UIControlStateNormal];
    [self.view addSubview:button];
    [button addTarget:self action:@selector(makeCrash:) forControlEvents:UIControlEventTouchUpInside];
    
}

- (void)makeCrash:(id)sender {
    NSArray *array = @[];
    NSLog(@"%@",array[1]);
}

@end
