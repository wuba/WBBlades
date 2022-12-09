//
//  ASFramework.h
//  AppSizeManager
//
//  Created by Shwnfee on 2022/2/21.
//

#import "ASBaseDirectory.h"
#import "ASMachOFile.h"
@interface ASFramework : ASBaseDirectory
@property (nonatomic, strong) ASMachOFile * exeFile;
@end

