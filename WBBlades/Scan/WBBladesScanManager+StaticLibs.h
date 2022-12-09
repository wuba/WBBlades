//
//  WBBladesScanManager+StaticLibs.h
//  WBBlades
//
//  Created by wbblades on 2022/4/27.
//

#import "WBBladesScanManager.h"
#import "WBBladesStaticLibraryModel.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (StaticLibs)

/**
 *  scan static library size
 *  @param fileData - binary data
 */
+ (WBBladesStaticLibraryModel *)scanStaticLibraryModel:(NSData *)fileData;
@end

NS_ASSUME_NONNULL_END
