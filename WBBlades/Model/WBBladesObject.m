//
//  WBBladesObject.m
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import "WBBladesObject.h"

@implementation WBBladesObjectMachO

@end

@implementation WBBladesObject

- (NSString *)description{
    NSString *string = [NSString stringWithFormat:@"\nNAME :  %@\n", self.objectHeader.longName];
    string = [string stringByAppendingString:[NSString stringWithFormat:@"SIZE :  %llu\n", self.objectMachO.size]];
    string = [string stringByAppendingString:[NSString stringWithFormat:@"RANGE:  (0x%lX,%lu)\n", (unsigned long)self.range.location, (unsigned long)self.range.length]];
    string = [string stringByAppendingString:[NSString stringWithFormat:@"SECTIONS:\n%@\n", self.objectMachO.sections]];
    string = [string stringByAppendingString:@"----------------------------------"];
    return string;
}

@end

@implementation WBBladesHelper

- (NSString *)description {
    NSString *string = [NSString stringWithFormat:@"%@  | ",self.className];
    string = [string stringByAppendingString:[NSString stringWithFormat:@"0x%lX",(unsigned long)self.offset]];
    return string;
}

@end

