//
//  AnalyzeCrashView.m
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeCrashView.h"

@implementation AnalyzeCrashView

- (instancetype)initWithFrame:(NSRect)frameRect{
    self = [super initWithFrame:frameRect];
    if (self) {
        [self prepareSubview];
    }
    return self;
}

- (void)prepareSubview{
    NSTextField *ipaLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0, 66, 36.0)];
    [self addSubview:ipaLabel];
    ipaLabel.font = [NSFont systemFontOfSize:14.0];
    ipaLabel.stringValue = @"IPA路径";
    ipaLabel.textColor = [NSColor blackColor];
    ipaLabel.editable = NO;
    ipaLabel.bezelStyle = NSBezelStyleTexturedSquare;
    ipaLabel.bordered = NO;
    ipaLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *textView = [[NSTextView alloc]initWithFrame:NSMakeRect(109.0, 434.0, 559.0, 36.0)];
    [self addSubview:textView];
    textView.font = [NSFont systemFontOfSize:14.0];
    textView.textColor = [NSColor blackColor];
    textView.wantsLayer = YES;
    textView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    textView.layer.borderWidth = 1.0;
    textView.layer.cornerRadius = 2.0;
    textView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSButton *ipaPreviewBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 432.0, 105.0, 40.0)];
    [self addSubview:ipaPreviewBtn];
    ipaPreviewBtn.title = @"选择文件夹";
    ipaPreviewBtn.font = [NSFont systemFontOfSize:14.0];
    ipaPreviewBtn.target = self;
    ipaPreviewBtn.action = @selector(ipaPreviewBtnClicked:);
    ipaPreviewBtn.bordered = YES;
    ipaPreviewBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextField *crashOriLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 364.0, 434.0, 38.0)];
    [self addSubview:crashOriLabel];
    crashOriLabel.font = [NSFont systemFontOfSize:14.0];
    crashOriLabel.stringValue = @"需要解析的堆栈（只粘贴需要解析的堆栈）";
    crashOriLabel.textColor = [NSColor blackColor];
    crashOriLabel.editable = NO;
    crashOriLabel.bordered = NO;
    crashOriLabel.backgroundColor = [NSColor clearColor];
    
    NSButton *startBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 376.0, 105.0, 40.0)];
    [self addSubview:startBtn];
    startBtn.title = @"开始解析";
    startBtn.font = [NSFont systemFontOfSize:14.0];
    startBtn.target = self;
    startBtn.action = @selector(startBtnClicked:);
    startBtn.bordered = YES;
    startBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextView *crashTextView = [[NSTextView alloc]initWithFrame:NSMakeRect(30.0, 214.0, 765.0, 148.0)];
    [self addSubview:crashTextView];
    crashTextView.font = [NSFont systemFontOfSize:14.0];
    crashTextView.textColor = [NSColor blackColor];
    crashTextView.wantsLayer = YES;
    crashTextView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    crashTextView.layer.borderWidth = 1.0;
    crashTextView.layer.cornerRadius = 2.0;
    crashTextView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSTextField *resultLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 161.0, 434.0, 38.0)];
    [self addSubview:resultLabel];
    resultLabel.font = [NSFont systemFontOfSize:14.0];
    resultLabel.stringValue = @"解析结果";
    resultLabel.textColor = [NSColor blackColor];
    resultLabel.editable = NO;
    resultLabel.bordered = NO;
    resultLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *resultTextView = [[NSTextView alloc]initWithFrame:NSMakeRect(30.0, 20.0, 765.0, 148.0)];
    [self addSubview:resultTextView];
    resultTextView.font = [NSFont systemFontOfSize:14.0];
    resultTextView.textColor = [NSColor blackColor];
    resultTextView.wantsLayer = YES;
    resultTextView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    resultTextView.layer.borderWidth = 1.0;
    resultTextView.layer.cornerRadius = 2.0;
    resultTextView.layer.borderColor = [NSColor lightGrayColor].CGColor;
}

- (void)ipaPreviewBtnClicked:(id)sender{
    NSLog(@"preview");
}

- (void)startBtnClicked:(id)sender{
     NSLog(@"start");
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    
    // Drawing code here.
}

@end
