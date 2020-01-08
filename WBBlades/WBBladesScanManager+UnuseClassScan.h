//
//  WBBladesScanManager+UnuseClassScan.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/8/5.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "WBBladesScanManager.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager (UnuseClassScan)

+ (NSSet *)scanAllClassWithFileData:(NSData*)fileData classes:(NSSet *)aimClasses;

+ (NSSet*)scanStaticLibraryForClassList:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
