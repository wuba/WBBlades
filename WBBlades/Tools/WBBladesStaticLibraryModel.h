//
//  WBBladesStaticLibraryModel.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2020/4/21.
//  Copyright © 2020 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesStaticLibraryModel : NSObject

@property (nonatomic, strong) NSMutableSet *undefinedSymbols;

@property (nonatomic, strong) NSMutableSet *definedSymbols;

@property (nonatomic, copy) NSString *name;

@property (nonatomic, assign) unsigned long long linkSize;

@end

NS_ASSUME_NONNULL_END
