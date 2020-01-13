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

//获取文件
+(NSData *)readFromFile:(NSString *)filePath;

//获取二进制文件，如果是app则直接读取其中的二进制，并对其做架构拆分
+(NSData *)readArm64FromFile:(NSString *)filePath;

@end

NS_ASSUME_NONNULL_END
