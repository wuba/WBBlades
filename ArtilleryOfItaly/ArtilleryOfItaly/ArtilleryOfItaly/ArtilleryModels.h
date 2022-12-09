//
//  ArtilleryModels.h
//  ArtilleryOfItaly
//
//  Created by 皮拉夫大王 on 2021/12/31.
//

#import <Foundation/Foundation.h>
#import "libdwarf.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesSymbolRangeArtillery : NSObject

@property (nonatomic, assign) unsigned long long begin;

@property (nonatomic, assign) unsigned long long end;

@property (nonatomic, copy) NSString *symbol;

@end

@interface WBBladesSymTabCommandArtillery : NSObject

@property (nonatomic, assign) unsigned int cmd;

@property (nonatomic, assign) unsigned int cmdsize;

@property (nonatomic, assign) unsigned int symbolOff;

@property (nonatomic, assign) unsigned int symbolNum;

@property (nonatomic, assign) unsigned int strOff;

@property (nonatomic, assign) unsigned int strSize;

@property (nonatomic, assign) unsigned int textSize;

@end

@interface SymbolInfo : NSObject

@property(nonatomic,assign) Dwarf_Unsigned begin;

@property(nonatomic,copy)NSString *file;

@property(nonatomic,copy)NSString *symbol;

@property(nonatomic,assign)Dwarf_Unsigned linenum;

@end

NS_ASSUME_NONNULL_END
