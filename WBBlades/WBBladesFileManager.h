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

+(NSData *)readFromFile:(NSString *)filePath;

@end

NS_ASSUME_NONNULL_END
