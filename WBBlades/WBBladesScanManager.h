//
//  WBBladesScanManager.h
//  WBBlades
//
//  Created by 邓竹立 on 2019/6/14.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesScanManager : NSObject

+ (unsigned long long)scanStaticLibrary:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END
