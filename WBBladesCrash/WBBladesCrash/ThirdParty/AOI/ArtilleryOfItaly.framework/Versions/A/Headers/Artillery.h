//
//  Artillery.h
//  ArtilleryOfItaly
//
//  Created by 邓竹立 on 2021/5/14.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Artillery : NSObject

+ (void)readDwarf:(NSString*)dwarfPath outputPath:(NSString*)ouput;

@end

NS_ASSUME_NONNULL_END
