//
//  AnalyzeCrashView.m
//  WBBlades
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeCrashView.h"

@interface AnalyzeCrashView()

@property (nonatomic,weak) NSTextView *ipaFileView;
@property (nonatomic,weak) NSTextView *crashStackView;

@end

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
    _ipaFileView = textView;
    
    NSButton *ipaPreviewBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 432.0, 105.0, 40.0)];
    [self addSubview:ipaPreviewBtn];
    ipaPreviewBtn.title = @"选择ipa文件";
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
    
    NSScrollView *scrollView = [[NSScrollView alloc]initWithFrame:NSMakeRect(30.0, 214.0, 765.0, 148.0)];
    [self addSubview:scrollView];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setBorderType:NSLineBorder];
    scrollView.wantsLayer = YES;
    scrollView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    scrollView.layer.borderWidth = 1.0;
    scrollView.layer.cornerRadius = 2.0;
    scrollView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSTextView *crashTextView = [[NSTextView alloc]initWithFrame:NSMakeRect(0, 0, 765.0, 148.0)];
     scrollView.documentView = crashTextView;
    crashTextView.font = [NSFont systemFontOfSize:14.0];
    crashTextView.textColor = [NSColor blackColor];
    _crashStackView = crashTextView;
    
    NSTextField *resultLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 161.0, 434.0, 38.0)];
    [self addSubview:resultLabel];
    resultLabel.font = [NSFont systemFontOfSize:14.0];
    resultLabel.stringValue = @"解析结果";
    resultLabel.textColor = [NSColor blackColor];
    resultLabel.editable = NO;
    resultLabel.bordered = NO;
    resultLabel.backgroundColor = [NSColor clearColor];
    
    NSScrollView *scrollView2 = [[NSScrollView alloc]initWithFrame:NSMakeRect(30.0, 20.0, 765.0, 148.0)];
    [self addSubview:scrollView2];
    [scrollView2 setHasVerticalScroller:YES];
    [scrollView2 setBorderType:NSLineBorder];
    scrollView2.wantsLayer = YES;
    scrollView2.layer.backgroundColor = [NSColor whiteColor].CGColor;
    scrollView2.layer.borderWidth = 1.0;
    scrollView2.layer.cornerRadius = 2.0;
    scrollView2.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSTextView *resultTextView = [[NSTextView alloc]initWithFrame:NSMakeRect(0, 0, 765.0, 148.0)];
    scrollView2.documentView = resultTextView;
    resultTextView.font = [NSFont systemFontOfSize:14.0];
    resultTextView.textColor = [NSColor blackColor];
}

- (void)ipaPreviewBtnClicked:(id)sender{
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt:@"选择ipa文件"];
    openPanel.allowsMultipleSelection = NO;
    openPanel.canChooseFiles = YES;
    openPanel.canChooseDirectories = NO;
    openPanel.directoryURL = nil;
    [openPanel setAllowedFileTypes:[NSArray arrayWithObjects:@"ipa", nil]];
    __weak __typeof(self) weakself = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        
        if (returnCode == 1 && [openPanel URLs]) {
            NSMutableString *fileFolders = [NSMutableString stringWithString:@""];
            NSArray *array = [openPanel URLs];
            for (NSInteger i = 0; i < array.count; i++) {
                NSURL *url = array[i];
                NSString *string = @",";
                if (i == array.count - 1) {
                    string = @"";
                }
                [fileFolders appendFormat:@"%@%@",url.absoluteString,string];
            }
            weakself.ipaFileView.string = [fileFolders copy];
            //weakself.ipaFileView.editable = NO;
        }
    }];
}

- (void)startBtnClicked:(id)sender{
    NSString *pureStr = [_ipaFileView.string stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSArray *paths = [pureStr componentsSeparatedByString:@".ipa"];
    
    if (!(paths.count == 2) || (paths.count == 2 && ![paths[1]  isEqual: @""])) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"好的"];
        [alert setMessageText:@"请选择或拖入一个.ipa文件"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        return;
    }
    
//    NSString *crashInfo = [_crashStackView.string stringByReplacingOccurrencesOfString:@" " withString:@""];
//    NSArray *crashComp = [crashInfo componentsSeparatedByString:@"+"];
//    NSString *crash = _crashStackView.string;
//    NSLog(@"%@", _crashStackView.string);
    NSArray *crashInfoLines = [_crashStackView.string componentsSeparatedByString:@"\n"];
    NSMutableArray *crashOffsets = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < crashInfoLines.count; i++) {
        NSString *crashLine = crashInfoLines[i];
        NSString *lineTrimmingSpace = [crashLine stringByReplacingOccurrencesOfString:@" " withString:@""];
        NSArray *comps = [lineTrimmingSpace componentsSeparatedByString:@"+"];
        NSString *offset = comps.lastObject;
        [crashOffsets addObject:[NSString stringWithString:offset]];
    }
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    
    // Drawing code here.
}

@end
