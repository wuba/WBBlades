//
//  ASFramework.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//

#import "ASFramework.h"
#import "ASFileManager.h"
@implementation ASFramework
+ (void)load{
    [[ASFileManager shareInstance] registerDirectoryModelClassString:NSStringFromClass([ASFramework class]) withDirectoryType:@"framework"];
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath{
    if (self = [super initWithDirectoryPath:directoryPath]) {
        if (self.current.machOFiles.count>0) {
            self.exeFile = [self.current.machOFiles firstObject];
        }
    }
    return self;
}


@end
