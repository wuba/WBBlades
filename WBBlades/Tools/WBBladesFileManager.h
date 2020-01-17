//
//  WBBladesFileManager.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesFileManager : NSObject

/** Get data from the file. */
+ (NSData *)readFromFile:(NSString *)filePath;

/**
 * Get the binary file. If it is an app, read the binary file directly and do the architecture split.
 * @return The arm64 architecture.
 */
+ (NSData *)readArm64FromFile:(NSString *)filePath;

@end

NS_ASSUME_NONNULL_END
