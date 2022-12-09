//
//  WBBladesCMD.h
//  WBBlades
//
//  Created by 皮拉夫大王 on 2019/12/25.
//  Copyright © 2019 58.com. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifdef    __cplusplus
extern "C" {
#endif

static NSData * cmd(NSString *cmd);

/**
 * Input file path, strip the symbol table.
 */
void stripBitCode(NSString *filePath);
void stripDysmSymbol(NSString *filePath);
/**
 * Input file path, copy the file.
 */
void copyFile(NSString *filePath);

/**
 * Input file path, strip multiple architectures and keep the arm64 architecture.
 */
void thinFile(NSString *filePath);

/**
 * Remove the file.
 */
void removeFile(NSString *filePath);

/**
 * Remove the copied file.
 */
void removeCopyFile(NSString *filePath);

/**
 * Compile xcassert resources.
 */
void compileXcassets(NSString *path);
/**
 app slicing 3X for Assets.Car
 */
void appSlicing3XAssetsCar(NSString *path, NSString *thinName);

/**
 * Color printing to console.
 * @param info Information to be printed.
 */
void colorPrint(NSString *info);

NSString* getAppPathIfIpa(NSString *filePath);

void rmAppIfIpa(NSString *filePath);

#ifdef    __cplusplus
}
#endif
