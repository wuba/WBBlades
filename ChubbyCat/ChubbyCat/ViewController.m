//
//  ViewController.m
//  ChubbyCat
//
//  Created by 邓竹立 on 2021/9/28.
//

#import "ViewController.h"
#import <objc/runtime.h>
#import "ChubbyCat-Swift.h"

@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    
    //Only 
    NSLog(@"call NSLog before hook");
    //do replace
    [[Test new] test];
    NSLog(@"call NSLog before after hook");
}
@end
