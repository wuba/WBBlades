//
//  NSString+Utils.m
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/21.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

#import "NSString+ASUtils.h"
#include <CommonCrypto/CommonDigest.h>

@implementation NSString(ASUtils)

- (NSString *)as_sha256Value{
    const char *s = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);
    NSData *outData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    NSMutableString *hash = [NSMutableString string];
    NSUInteger length = [outData length];
    char *bytes = malloc(sizeof(char) * length);
    [outData getBytes:bytes length:length];
    for (int i = 0; i < length; i++) {
        [hash appendFormat:@"%02.2hhX", bytes[i]];
    }
    free(bytes);
    return hash;
}

+ (NSString *)as_getFileSHA256StrFromPath:(NSString *)path
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if([fileManager fileExistsAtPath:path isDirectory:nil])
    {
        NSData *keyData = [NSData dataWithContentsOfFile:path];
        uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
        CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);
        NSData *outData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        NSMutableString *hash = [NSMutableString string];
        NSUInteger length = [outData length];
        char *bytes = (char *)malloc(sizeof(char) * length);
        [outData getBytes:bytes length:length];
        for (int i = 0; i < length; i++) {
            [hash appendFormat:@"%02.2hhX", bytes[i]];
        }
        free(bytes);
        return hash;
    }
    else
    {
        return @"";
    }
}

@end
