//
//  WBBladesSymTab.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/6/15.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesSymbol : NSObject

@property (nonatomic, assign) unsigned int symbolIndex;

@property (nonatomic, assign) unsigned int offset;

@end

@interface WBBladesSymTab : NSObject

@property (nonatomic, assign) unsigned int size;

@property (nonatomic, strong) NSArray <WBBladesSymbol *>*symbols;

@property (nonatomic, assign) NSRange range;

@end

@interface WBBladesSymTabCommand : NSObject

@property (nonatomic, assign) unsigned int cmd;

@property (nonatomic, assign) unsigned int cmdsize;

@property (nonatomic, assign) unsigned int symbolOff;

@property (nonatomic, assign) unsigned int symbolNum;

@property (nonatomic, assign) unsigned int strOff;

@property (nonatomic, assign) unsigned int strSize;

@property (nonatomic, assign) unsigned int textSize;

@property (nonatomic, assign) BOOL withDWARF;

@end

@interface WBBladesSymbolRange : NSObject

@property (nonatomic, assign) unsigned long long begin;

@property (nonatomic, assign) unsigned long long end;

@property (nonatomic, copy) NSString *symbol;

@end

@interface WBBladesMethodRange : NSObject

@property (nonatomic, assign) unsigned long long begin;

@property (nonatomic, assign) unsigned long long end;
@property (nonatomic, assign) NSInteger lastInd;


@end

NS_ASSUME_NONNULL_END
