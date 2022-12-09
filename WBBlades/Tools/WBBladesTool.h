//
//  WBBladesTool.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/12/30.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "WBBladesDefines.h"
#import "capstone.h"
#import <mach-o/loader.h>


NS_ASSUME_NONNULL_BEGIN

@interface WBBladesTool : NSObject

#ifdef __cplusplus
/**
 * Return an array contains continuous strings from the file data.
 * See method implementation for details.
 */
+ (NSArray *)readStrings:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

/**
 * Return a single string from the file data.
 * @param range Indicate the start location of the buffer storing the string.
 * @param len The actural size of the buffer.
 * @param fileData The file data to be read from.
 * @return The string in the file data start at the end of the range whose size is len.
 */
+ (NSString *)readString:(NSRange &)range fixlen:(NSUInteger)len fromFile:(NSData *)fileData;

/**
 * Return bytes data from the file data.
 */
+ (NSData *)readBytes:(NSRange &)range length:(NSUInteger)length fromFile:(NSData *)fileData;
#endif //__cplusplus

/**
 * Replace the escape characters in the input string.
 */
+ (NSString *)replaceEscapeCharsInString:(NSString *)orig;

/**
 * disassembly
 */
+ (NSArray *)disassemWithMachOFile:(NSData *)fileData  from:(unsigned long long)begin length:(unsigned long long )size accfunDic:(NSDictionary *)accfunDic;

/**
* bind info
*/
+ (NSDictionary *)dynamicBindingInfoFromFile:(NSData *)fileData;
+ (NSArray *)dylibNamesFromFile:(NSData *)fileData;

+ (unsigned long long)getSectionMigrateOffset:(unsigned long long)address andBaseAddr:(unsigned long long)vm fileData:(NSData *)fileData;

/**
* convert address from vm to offset
*/
+ (unsigned long long)getOffsetFromVmAddress:(unsigned long long )address fileData:(NSData *)fileData;

/**
*  support 64bit  Mach-O file
*/
+ (BOOL)isSupport:(NSData *)fileData;

/**
*  is  Mach-O file
*/
+ (BOOL)isMachO:(NSData *)fileData;

/**
* check swift Type
*/
+ (SwiftKind)getSwiftType:(SwiftType)type;

/**
* check swift  method Kind
*/
+ (SwiftMethodKind)getSwiftMethodKind:(SwiftMethod)method;

/**
* check swift  method Type
*/
+ (SwiftMethodType)getSwiftMethodType:(SwiftMethod)method;

/**
* get swift type name
*/
+ (NSString *)getSwiftTypeNameWithSwiftType:(SwiftType)type Offset:(uintptr_t)offset vm:(uintptr_t)vm fileData:(NSData*)fileData;

/**
* check swift  protocol table Kind
*/
+ (SwiftProtocolTableKind)getSwiftProtocolTableKind:(SwiftMethod)method;

/**
* check swift  protocol table Type
*/
+ (SwiftProtocolTableType)getSwiftProtocolTableType:(SwiftMethod)method;

/**
* hasVTable
*/
+ (BOOL)hasVTable:(SwiftType)type;

/**
* hasOverrideTable
*/
+ (BOOL)hasOverrideTable:(SwiftType)type;

/**
* hasSingletonMetadataInitialization
*/
+ (BOOL)hasSingletonMetadataInitialization:(SwiftType)type;

/**
* isgetGeneric
*/
+ (BOOL)isGeneric:(SwiftType)type;

/**
* isgetGeneric
*/
+ (BOOL)isGenericType:(SwiftBaseType)type;

/**
* get demangle name
*/
+ (NSString *)getDemangleName:(NSString *)mangleName;

/**
* get demangle name
*/
+ (NSString *)getDemangleNameWithCString:(char *)mangleName;
/**
*  reversal data
*/
+ (void*)mallocReversalData:(uintptr_t)data length:(int)length;

/**
*generic data length
*/
+ (short)addPlaceholderWithGeneric:(unsigned long long)typeOffset fileData:(NSData*)fileData;

/**
*get methodNum location
*/
+ (uintptr_t)methodNumLocation:(SwiftType)baseType offset:(uintptr_t)typeOffset fileData:(NSData *)fileData;

+ (BOOL)anonymousHasMangledName:(SwiftType)baseType;

+ (UInt32)sectionFlagsWithIndex:(int)index fileData:(NSData *)fileData;

+ (section_64)getTEXTConst:(unsigned long long )address fileData:(NSData *)fileData;

@end

NS_ASSUME_NONNULL_END

