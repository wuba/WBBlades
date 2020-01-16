//
//  WBBladesStringTab.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/15.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WBBladesStringTab : NSObject

@property (nonatomic, assign) unsigned int size;

@property (nonatomic, strong) NSArray<NSString *> *strings;

@property (nonatomic, assign) NSRange range;

@end

