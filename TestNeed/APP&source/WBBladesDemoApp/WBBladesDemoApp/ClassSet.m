//
//  ClassSet.m
//  WBBladesDemoApp
//
//  Created by 邓竹立 on 2020/1/14.
//  Copyright © 2020 邓竹立. All rights reserved.
//
#import "ClassSet.h"
#import "ViewController.h"
#import "SceneDelegate.h"

@interface ClassSet ()

@property(nonatomic,strong)SceneDelegate *delegate;

@property(nonatomic,strong)NSMutableArray *array;

@end

@implementation ClassSet

- (instancetype)init{
    if (self = [super init]) {
        _array = [NSMutableArray array];
    }
    return self;
}

- (void)testUse{
    ClassSet *set = [[ClassSet alloc] init];
    [self.array addObject:set];
}

@end

