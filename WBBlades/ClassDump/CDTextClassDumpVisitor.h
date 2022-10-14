// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDVisitor.h"

// Has a mutable string for storing output, and method to write it to standard out.
// symbol references are for... ?

@class CDOCProperty, CDType;
@interface CDTextClassDumpVisitor : CDVisitor

@property (nonatomic, strong) NSMutableString *resultString;
- (void)visitProperty:(CDOCProperty *)property parsedType:(CDType *)parsedType attributes:(NSArray *)attrs;
- (void)visitIvar:(CDOCInstanceVariable *)ivar;
- (void)writeResultToStandardOutput;

@end
