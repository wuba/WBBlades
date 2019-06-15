//
//  WBBladesSymTab.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/15.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


@interface WBBladesSymbol : NSObject

@property(nonatomic,assign)unsigned int symbolIndex;

@property(nonatomic,assign)unsigned int offset;

@end

@interface WBBladesSymTab : NSObject

@property(nonatomic,assign)unsigned int size;

@property(nonatomic,strong)NSArray<WBBladesSymbol*>* symbols;

@property(nonatomic,assign)NSRange range;

@end

NS_ASSUME_NONNULL_END
