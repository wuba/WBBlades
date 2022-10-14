// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.



@class CDOCClassReference;

@interface CDOCClass : NSObject

@property (strong) CDOCClassReference *superClassRef;
@property (copy, readonly) NSString *superClassName;
@property (strong) NSArray *instanceVariables;
@property (assign) BOOL isExported;
@property (assign) BOOL isSwiftClass;

@end
