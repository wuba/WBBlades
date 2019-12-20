//
//  AnalyzeLibView.m
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeLibView.h"

@implementation AnalyzeLibView

- (instancetype)initWithFrame:(NSRect)frameRect{
    self = [super initWithFrame:frameRect];
    if (self) {
         [self prepareSubview];
    }
    return self;
}

- (void)prepareSubview{
    NSTextField *pathLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0, 66, 36.0)];
    [self addSubview:pathLabel];
    pathLabel.font = [NSFont systemFontOfSize:14.0];
    pathLabel.stringValue = @"目标路径";
    pathLabel.textColor = [NSColor blackColor];
    pathLabel.editable = NO;
    pathLabel.bezelStyle = NSBezelStyleTexturedSquare;
    pathLabel.bordered = NO;
    pathLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *textView = [[NSTextView alloc]initWithFrame:NSMakeRect(109.0, 434.0, 559.0, 36.0)];
    [self addSubview:textView];
    textView.font = [NSFont systemFontOfSize:14.0];
    textView.textColor = [NSColor blackColor];
    textView.wantsLayer = YES;
    textView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    textView.layer.borderWidth = 1.0;
    textView.layer.cornerRadius = 2.0;
    textView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSButton *pathBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 432.0, 105.0, 40.0)];
    [self addSubview:pathBtn];
    pathBtn.title = @"选择文件夹";
    pathBtn.font = [NSFont systemFontOfSize:14.0];
    pathBtn.target = self;
    pathBtn.action = @selector(pathBtnClicked:);
    pathBtn.bordered = YES;
    pathBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextField *outputLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 374.0, 66, 36.0)];
    [self addSubview:outputLabel];
    outputLabel.font = [NSFont systemFontOfSize:14.0];
    outputLabel.stringValue = @"输出路径";
    outputLabel.textColor = [NSColor blackColor];
    outputLabel.editable = NO;
    outputLabel.bordered = NO;
    outputLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *outputView = [[NSTextView alloc]initWithFrame:NSMakeRect(109.0, 384.0, 559.0, 36.0)];
    [self addSubview:outputView];
    outputView.font = [NSFont systemFontOfSize:14.0];
    outputView.textColor = [NSColor blackColor];
    outputView.wantsLayer = YES;
    outputView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    outputView.layer.borderWidth = 1.0;
    outputView.layer.cornerRadius = 2.0;
    outputView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSButton *outputBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 382.0, 105.0, 40.0)];
    [self addSubview:outputBtn];
    outputBtn.title = @"选择文件夹";
    outputBtn.font = [NSFont systemFontOfSize:14.0];
    outputBtn.target = self;
    outputBtn.action = @selector(outputBtnClicked:);
    outputBtn.bordered = YES;
    outputBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextField *progressLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 320.0, 66, 36.0)];
    [self addSubview:progressLabel];
    progressLabel.font = [NSFont systemFontOfSize:14.0];
    progressLabel.stringValue = @"进度：";
    progressLabel.textColor = [NSColor blackColor];
    progressLabel.editable = NO;
    progressLabel.bordered = NO;
    progressLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *consoleView = [[NSTextView alloc]initWithFrame:NSMakeRect(30.0, 32.0, 638.0, 279.0)];
    [self addSubview:consoleView];
    consoleView.font = [NSFont systemFontOfSize:14.0];
    consoleView.textColor = [NSColor blackColor];
    consoleView.wantsLayer = YES;
    consoleView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    consoleView.layer.borderWidth = 1.0;
    consoleView.layer.cornerRadius = 2.0;
    consoleView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSButton *startBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 273.0, 105.0, 40.0)];
    [self addSubview:startBtn];
    startBtn.title = @"开始分析";
    startBtn.font = [NSFont systemFontOfSize:14.0];
    startBtn.target = self;
    startBtn.action = @selector(startBtnClicked:);
    startBtn.bordered = YES;
    startBtn.bezelStyle = NSBezelStyleRegularSquare;

    NSButton *stopBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 210.0, 105.0, 40.0)];
    [self addSubview:stopBtn];
    stopBtn.title = @"暂停分析";
    stopBtn.font = [NSFont systemFontOfSize:14.0];
    stopBtn.target = self;
    stopBtn.action = @selector(stopBtnClicked:);
    stopBtn.bordered = YES;
    stopBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSButton *inFinderBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 147.0, 105.0, 40.0)];
    [self addSubview:inFinderBtn];
    inFinderBtn.title = @"打开文件夹";
    inFinderBtn.font = [NSFont systemFontOfSize:14.0];
    inFinderBtn.target = self;
    inFinderBtn.action = @selector(inFinderBtnClicked:);
    inFinderBtn.bordered = YES;
    inFinderBtn.bezelStyle = NSBezelStyleRegularSquare;
    inFinderBtn.enabled = NO;
}

- (void)pathBtnClicked:(id)sender{
    NSLog(@"path");
}

- (void)outputBtnClicked:(id)sender{
    NSLog(@"output");
}

- (void)startBtnClicked:(id)sender{
    NSLog(@"start");
}

- (void)stopBtnClicked:(id)sender{
    NSLog(@"stop");
}

- (void)inFinderBtnClicked:(id)sender{
    NSLog(@"finder");
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    
    // Drawing code here.
}

@end
