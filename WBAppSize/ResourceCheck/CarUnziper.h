//
//  cartool
//
//  Created by Steven Troughton-Smith on 14/07/2013.
//  Copyright (c) 2013 High Caffeine Content. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface CarUnziper : NSObject
+ (void)exportWithCarPath:(NSString *)carPath withOutPutPath:(NSString *)outputDirectoryPath;
+ (void)exportWithCarPath:(NSString *)carPath withOutPutPath:(NSString *)outputDirectoryPath fileNameSHA256InfoCallBack:(void(^)(NSDictionary * fileNameSHA256Info))callBack;

+ (void)exportWithCarPath:(NSString *)carPath withOutPutPath:(NSString *)outputDirectoryPath assetInfos:(NSDictionary *)assetsInfo fileNameSHA256InfoCallBack:(void(^)(NSDictionary * fileNameSHA256Info))callBack;


@end
