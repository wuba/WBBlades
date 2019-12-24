//
//  ViewController.m
//  WBBlades
//
//  Created by 邓竹立 on 2019/12/19.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@property(nonatomic,strong)NSTask *bladesTask;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    
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
