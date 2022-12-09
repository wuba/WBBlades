//
//  WBBladesStringTab.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface WBBladesStringTab : NSObject

@property (nonatomic, assign) unsigned int size;

@property (nonatomic, strong) NSArray<NSString *> *strings;

@property (nonatomic, assign) NSRange range;

@end

