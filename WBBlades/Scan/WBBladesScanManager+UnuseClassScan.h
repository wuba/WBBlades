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

/*
 * scan specified file to find unused classes
 * @param fileData binary data
 * @param aimClasses specified class
 * @param scanProgressBlock provide some progress info
 */
+ (NSSet *)scanAllClassWithFileData:(NSData*)fileData classes:(NSSet *)aimClasses progressBlock:(void (^)(NSString *progressInfo))scanProgressBlock;

/*
* dump binary file's classes
* @param fileData binary data
*/
+ (NSSet *)dumpClassList:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
