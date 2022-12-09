//
//  cartool
//
//  Created by Steven Troughton-Smith on 14/07/2013.
//  Copyright (c) 2013 High Caffeine Content. All rights reserved.
//

#import "CarUnziper.h"
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#import "NSString+ASUtils.h"
typedef enum _kCoreThemeIdiom {
    kCoreThemeIdiomUniversal,
    kCoreThemeIdiomPhone,
    kCoreThemeIdiomPad,
    kCoreThemeIdiomTV,
    kCoreThemeIdiomCar,
    kCoreThemeIdiomWatch,
    kCoreThemeIdiomMarketing
} kCoreThemeIdiom;

typedef NS_ENUM(NSInteger, UIUserInterfaceSizeClass) {
    UIUserInterfaceSizeClassUnspecified = 0,
    UIUserInterfaceSizeClassCompact     = 1,
    UIUserInterfaceSizeClassRegular     = 2,
};

@interface CUICommonAssetStorage : NSObject

-(NSArray *)allAssetKeys;
-(NSArray *)allRenditionNames;

-(id)initWithPath:(NSString *)p;

-(NSString *)versionString;

@end

@interface CUINamedImage : NSObject

@property(readonly) CGSize size;
@property(readonly) CGFloat scale;
@property(readonly) kCoreThemeIdiom idiom;
@property(readonly) UIUserInterfaceSizeClass sizeClassHorizontal;
@property(readonly) UIUserInterfaceSizeClass sizeClassVertical;

-(CGImageRef)image;

@end

@interface CUIRenditionKey : NSObject
@end

@interface CUIThemeFacet : NSObject

+(CUIThemeFacet *)themeWithContentsOfURL:(NSURL *)u error:(NSError **)e;

@end

@interface CUICatalog : NSObject

@property(readonly) bool isVectorBased;

-(id)initWithName:(NSString *)n fromBundle:(NSBundle *)b;
-(id)allKeys;
-(id)allImageNames;
-(CUINamedImage *)imageWithName:(NSString *)n scaleFactor:(CGFloat)s;
-(CUINamedImage *)imageWithName:(NSString *)n scaleFactor:(CGFloat)s deviceIdiom:(int)idiom;
-(NSArray *)imagesWithName:(NSString *)n;
-(id)initWithURL:(NSURL *)URL error:(NSError **)error;

@end


@implementation CarUnziper
+ (void)CGImage:(CGImageRef )image writeToFile:(NSString *)path{
    [self CGImage:image writeToFile:path byType:nil];
}

+ (void)CGImage:(CGImageRef )image writeToFile:(NSString *)path byType:(CFStringRef)type
{
    if (!type) {
        type = kUTTypePNG;
    }
    CFURLRef url = (__bridge CFURLRef)[NSURL fileURLWithPath:path];
    CGImageDestinationRef destination = CGImageDestinationCreateWithURL(url, type, 1, NULL);
    CGImageDestinationAddImage(destination, image, nil);
    
    if (!CGImageDestinationFinalize(destination)) {
        NSLog(@"Failed to write image to %@", path);
    }
//    CFRelease(destination);
}

+ (NSString *)idiomSuffixForCoreThemeIdiom:(kCoreThemeIdiom)idiom
{
    switch (idiom) {
        case kCoreThemeIdiomUniversal:
            return @"";
            break;
        case kCoreThemeIdiomPhone:
            return @"~iphone";
            break;
        case kCoreThemeIdiomPad:
            return @"~ipad";
            break;
        case kCoreThemeIdiomTV:
            return @"~tv";
            break;
        case kCoreThemeIdiomCar:
            return @"~carplay";
            break;
        case kCoreThemeIdiomWatch:
            return @"~watch";
            break;
        case kCoreThemeIdiomMarketing:
            return @"~marketing";
            break;
        default:
            break;
    }
    return @"";
}

+ (NSString *)sizeClassSuffixForSizeClass:(UIUserInterfaceSizeClass)sizeClass
{
    switch (sizeClass)
    {
        case UIUserInterfaceSizeClassCompact:
            return @"C";
            break;
        case UIUserInterfaceSizeClassRegular:
            return @"R";
            break;
        default:
            return @"A";
    }
}

+ (NSMutableArray *)getImagesArrayWithCatalog:(CUICatalog *)catalog  andKey:(NSString *)key
{
    NSMutableArray *images = [[NSMutableArray alloc] initWithCapacity:5];

    for (NSNumber *scaleFactor in @[@1, @2, @3])
    {
        CUINamedImage *image = [catalog imageWithName:key scaleFactor:scaleFactor.doubleValue];

        if (image && image.scale == scaleFactor.floatValue) [images addObject:image];
    }

    return images;
}

+ (void)exportWithCarPath:(NSString *)carPath withOutPutPath:(NSString *)outputDirectoryPath assetInfos:(NSDictionary *)assetInfos fileNameSHA256InfoCallBack:(void(^)(NSDictionary * fileNameSHA256Info))callBack{
    NSMutableDictionary * fileNameSHA256Info;
    if (callBack) {
        fileNameSHA256Info = [NSMutableDictionary dictionary];
    }
    NSFileManager * fm = [NSFileManager defaultManager];
    BOOL isDirectory = NO;
    if (![fm fileExistsAtPath:outputDirectoryPath isDirectory:&isDirectory]) {
        [fm createDirectoryAtPath:outputDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    NSError *error = nil;
    outputDirectoryPath = [outputDirectoryPath stringByExpandingTildeInPath];
    
    CUICatalog *catalog = nil;
    if ([NSClassFromString(@"CUICatalog") instancesRespondToSelector:@selector(initWithURL:error:)]) {
        /* If CUICatalog has the URL API (Mojave), use it. */
        catalog = [[NSClassFromString(@"CUICatalog") alloc] initWithURL:[NSURL fileURLWithPath:carPath] error:&error];
        
    } else {
        CUIThemeFacet *facet = [NSClassFromString(@"CUIThemeFacet") themeWithContentsOfURL:[NSURL fileURLWithPath:carPath] error:&error];
        catalog = [[NSClassFromString(@"CUICatalog") alloc] init];
        /* Override CUICatalog to point to a file rather than a bundle */
        [catalog setValue:facet forKey:@"_storageRef"];
    }
    
    /* CUICommonAssetStorage won't link */
    CUICommonAssetStorage *storage = [[NSClassFromString(@"CUICommonAssetStorage") alloc] initWithPath:carPath];
    
    for (NSString *key in [storage allRenditionNames])
    {
//        printf("%s\n", [key UTF8String]);
        
        NSArray* pathComponents = [key pathComponents];
        if (pathComponents.count > 1)
        {
            // Create subdirectories for namespaced assets (those with names like "some/namespace/image-name")
            NSArray* subdirectoryComponents = [pathComponents subarrayWithRange:NSMakeRange(0, pathComponents.count - 1)];
            
            NSString* subdirectoryPath = [outputDirectoryPath copy];
            for (NSString* pathComponent in subdirectoryComponents)
            {
                subdirectoryPath = [subdirectoryPath stringByAppendingPathComponent:pathComponent];
            }
            
            [[NSFileManager defaultManager] createDirectoryAtPath:subdirectoryPath
                                      withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:&error];
        }
        NSMutableArray *images =  [[self class] getImagesArrayWithCatalog:catalog andKey:key];
        
        
        for( CUINamedImage *image in images )
        {
            @autoreleasepool {
                if( CGSizeEqualToSize(image.size, CGSizeZero) ){
                    printf("\tnil image?\n");
                }
                else
                {
                    CGImageRef cgImage = [image image];
                    NSString *idiomSuffix = [[self class] idiomSuffixForCoreThemeIdiom:image.idiom];
                    
                    NSString *sizeClassSuffix = @"";
                    
                    if (image.sizeClassHorizontal || image.sizeClassVertical)
                    {
                        sizeClassSuffix = [NSString stringWithFormat:@"-%@x%@", [[self class] sizeClassSuffixForSizeClass:image.sizeClassHorizontal],[[self class] sizeClassSuffixForSizeClass:image.sizeClassVertical]];
                    }
                    
                    NSString *scale = image.scale > 1.0 ? [NSString stringWithFormat:@"@%dx", (int)floor(image.scale)] : @"";
                    
                    NSString *fileName = [NSString stringWithFormat:@"%@%@%@%@", key, idiomSuffix, sizeClassSuffix, scale];
                    NSString *name = [NSString stringWithFormat:@"%@.png", fileName];
                    
                    
//                    printf("\t%s\n", [name UTF8String]);
                    NSString * sha256Key = fileName;
                    if (fileNameSHA256Info) {
                        sha256Key = [NSString stringWithFormat:@"%@",[fileName as_sha256Value]];
                        fileNameSHA256Info[sha256Key] = name;
                        name = [NSString stringWithFormat:@"%@.png", sha256Key];
                    }
                    if( outputDirectoryPath )
                    {
                        CFStringRef outputType = kUTTypePNG;
                        if (assetInfos && assetInfos[fileName]) {
                            NSDictionary * assetsInfo = assetInfos[fileName];
                            NSString * type = assetsInfo[@"Encoding"];
                            if ([type isEqualToString:@"JPEG"]) {
                                outputType = kUTTypeJPEG;
                                name = [NSString stringWithFormat:@"%@.jpg", fileName];
                                fileNameSHA256Info[sha256Key] = name;
                                name = [NSString stringWithFormat:@"%@.jpg", sha256Key];
                            }
                        }
                        [[self class] CGImage:cgImage writeToFile:[outputDirectoryPath stringByAppendingPathComponent:name] byType:outputType];
                    }
                }
            }
        }
    }
    if (callBack) {
        callBack(fileNameSHA256Info);
    }
}

+ (void)exportWithCarPath:(NSString *)carPath withOutPutPath:(NSString *)outputDirectoryPath{
    [self exportWithCarPath:carPath withOutPutPath:outputDirectoryPath assetInfos:nil fileNameSHA256InfoCallBack:nil];
}

@end
