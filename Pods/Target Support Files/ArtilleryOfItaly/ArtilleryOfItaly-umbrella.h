#ifdef __OBJC__
#import <Cocoa/Cocoa.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "Artillery.h"
#import "ArtilleryModels.h"
#import "ArtilleryOfItaly.h"
#import "dwarf.h"
#import "libdwarf.h"

FOUNDATION_EXPORT double ArtilleryOfItalyVersionNumber;
FOUNDATION_EXPORT const unsigned char ArtilleryOfItalyVersionString[];

