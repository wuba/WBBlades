//
//  ChainFixUpsHelper.h
//  WBBlades
//
//  Created by wbblades on 2022/8/4.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import <Foundation/Foundation.h>

@interface WBSectionRangeModel : NSObject
@property (nonatomic, assign)NSInteger  startRange;
@property (nonatomic, assign)NSInteger  endRange;
@end


NS_ASSUME_NONNULL_BEGIN

#define ChainFixUpsRawvalueMask  0x00000000ffffffff

@interface WBChainFixupImportSymbol : NSObject
@property (nonatomic, copy)NSString * dylibName;
@property (nonatomic, copy)NSString * importSymbolName;
@end

@interface ChainFixUpsHelper : NSObject

@property (nonatomic, assign)BOOL  isChainFixups;
@property (nonatomic, strong)NSMutableArray<NSString *> *dylibNames;
@property (nonatomic, strong)NSMutableArray<WBChainFixupImportSymbol *> *importSymbolPool;
@property (nonatomic, strong)NSMutableArray<NSString *> *segmentNames;
@property (nonatomic, strong)NSMutableDictionary<NSString *,WBSectionRangeModel *> *sectionRangeMap;
@property (nonatomic, strong)NSMutableDictionary<NSNumber *, WBChainFixupImportSymbol *> *bindAdreesInfos;

+(ChainFixUpsHelper *)shareInstance;

-(ChainFixUpsHelper *)fileLoaderWithFileData:(NSData *)fileData;

-(BOOL)validateSectionWithFileoffset:(long long )offset sectionName:(NSString *)name;

@end

NS_ASSUME_NONNULL_END
