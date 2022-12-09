//
//  WBBladesFileManager+StaticLibs.h
//  WBBlades
//
//  Created by wbblades on 2022/4/27.
//

#import "WBBladesFileManager.h"
#import "WBBladesStaticLibraryModel.h"

NS_ASSUME_NONNULL_BEGIN

@interface WBBladesFileManager (StaticLibs)

+ (WBBladesStaticLibraryModel *)scanFrameworkWithOriginalPath:(NSString *)path
                                                frameworkName:(NSString *)frameworkName;
+ (WBBladesStaticLibraryModel *)scanStaticLibWithOriginalPath:(NSString *)path
                                                frameworkName:(NSString *)frameworkName;

@end

NS_ASSUME_NONNULL_END
