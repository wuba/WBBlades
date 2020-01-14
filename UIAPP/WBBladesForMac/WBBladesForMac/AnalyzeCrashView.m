//
//  AnalyzeCrashView.m
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeCrashView.h"

@interface AnalyzeCrashView()

@property (nonatomic,weak) NSTextView *exeFileView;
@property (nonatomic,weak) NSTextView *crashStackView;
@property (nonatomic,weak) NSTextView *resultView;
@property (nonatomic,copy) NSMutableArray *crashStacks;
@property (nonatomic,copy) NSMutableArray *usefulCrashStacks;
@property (nonatomic,weak) NSButton *startButton;

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
    _crashStacks = [[NSMutableArray alloc] init];
    _usefulCrashStacks = [[NSMutableArray alloc] init];
    
    NSTextField *exeLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0, 80, 36.0)];
    [self addSubview:exeLabel];
    exeLabel.font = [NSFont systemFontOfSize:14.0];
    exeLabel.stringValue = @"可执行文件路径";
    exeLabel.alignment = NSTextAlignmentCenter;
    exeLabel.textColor = [NSColor blackColor];
    exeLabel.editable = NO;
    exeLabel.bezelStyle = NSBezelStyleTexturedSquare;
    exeLabel.bordered = NO;
    exeLabel.backgroundColor = [NSColor clearColor];
    
    NSTextView *textView = [[NSTextView alloc]initWithFrame:NSMakeRect(109.0, 434.0, 559.0, 36.0)];
    [self addSubview:textView];
    textView.font = [NSFont systemFontOfSize:14.0];
    textView.textColor = [NSColor blackColor];
    textView.wantsLayer = YES;
    textView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    textView.layer.borderWidth = 1.0;
    textView.layer.cornerRadius = 2.0;
    textView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    _exeFileView = textView;
    
    NSButton *ipaPreviewBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 432.0, 105.0, 40.0)];
    [self addSubview:ipaPreviewBtn];
    ipaPreviewBtn.title = @"选择文件";
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
    _startButton = startBtn;
    
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
    resultTextView.editable = NO;
    _resultView = resultTextView;
}

- (void)ipaPreviewBtnClicked:(id)sender{
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt:@"选择可执行文件"];
    openPanel.allowsMultipleSelection = NO;
    openPanel.canChooseFiles = YES;
    openPanel.canChooseDirectories = YES;
    openPanel.directoryURL = nil;
    [openPanel setAllowedFileTypes:[NSArray arrayWithObjects:@"", nil]];
    __weak __typeof(self) weakself = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        
        if (returnCode == 1 && [openPanel URLs]) {
            NSMutableString *fileFolders = [NSMutableString stringWithString:@""];
            NSArray *array = [openPanel URLs];
            for (NSInteger i = 0; i < array.count; i++) {
                NSURL *url = array[i];
                NSString *urlString = [url.absoluteString substringFromIndex:7];
                NSString *string = @",";
                if (i == array.count - 1) {
                    string = @"";
                }
                [fileFolders appendFormat:@"%@%@",urlString,string];
            }
            weakself.exeFileView.string = [fileFolders copy];
            //weakself.ipaFileView.editable = NO;
        }
    }];
}

- (void)startBtnClicked:(id)sender{
    
    _resultView.string = @"";
    _startButton.enabled = NO;
    _crashStackView.editable = NO;
    NSURL *fileUrl = [NSURL fileURLWithPath:_exeFileView.string];
    NSData *fileData = [NSMutableData dataWithContentsOfURL:fileUrl];
    if (!fileData) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"好的"];
        [alert setMessageText:@"请选择或拖入一个可执行文件"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        _startButton.enabled = YES;
        _crashStackView.editable = YES;
        return;
    }
    
    // 获得可执行文件的名称
    NSString *execName = [_exeFileView.string componentsSeparatedByString:@"/"].lastObject;
    
    // 获得此app的崩溃地址
    NSArray *crashInfoLines = [_crashStackView.string componentsSeparatedByString:@"\n"];
    NSMutableArray *crashOffsets = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < crashInfoLines.count; i++) {
        
        NSString *crashLine = crashInfoLines[i];
        NSMutableArray *compos = [[crashLine componentsSeparatedByString:@" "] mutableCopy];
        [compos removeObject:@""];
        if (compos.count > 2) {
            NSString *appName = compos[1];
            if ([appName isEqualToString:execName]) {
                NSString *lineTrimmingSpace = [crashLine stringByReplacingOccurrencesOfString:@" " withString:@""];
                NSArray *comps = [lineTrimmingSpace componentsSeparatedByString:@"+"];
                NSString *offset = comps.lastObject;
                if(offset.longLongValue) {
                    [crashOffsets addObject:[NSString stringWithString:offset]];
                }
                [_usefulCrashStacks addObject:crashLine];
            }
        }
        [_crashStacks addObject:crashLine];
        
    }
    if (crashOffsets.count > 0) {
        NSString *offsets = [crashOffsets componentsJoinedByString:@","];
        [self analyzeCrashFromOffsets:offsets];
    } else {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"好的"];
        [alert setMessageText:@"请粘贴崩溃堆栈"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        _startButton.enabled = YES;
        _crashStackView.editable = YES;
        return;
    }
}

-(void)analyzeCrashFromOffsets:(NSString*)offsets {
    _resultView.string = @"解析中，请稍候";
    
    __weak typeof(self) weakSelf = self;
    NSString *inputFile = _exeFileView.string;

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *path = [[NSBundle mainBundle] pathForResource:@"WBBlades" ofType:@""];
        NSTask *bladesTask = [[NSTask alloc] init];
        [bladesTask setLaunchPath:path];
        [bladesTask setArguments:[NSArray arrayWithObjects:@"3", [NSString stringWithString:inputFile], [NSString stringWithString:offsets], nil]];
        NSPipe *pipe;
        pipe = [NSPipe pipe];
        [bladesTask setStandardOutput:pipe];
        NSFileHandle *file;
        file = [pipe fileHandleForReading];
        [bladesTask launch];
        NSData *data;
        data = [file readDataToEndOfFile];
        NSDictionary * resultsDic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:nil];
        [bladesTask waitUntilExit];
        dispatch_async(dispatch_get_main_queue(), ^{
            [bladesTask terminate];
            [weakSelf outputResults:resultsDic];
        });
    });
    
 
}

- (void)outputResults:(NSDictionary*)resultDic {
    _startButton.enabled = YES;
    _crashStackView.editable = YES;
    NSMutableArray *outputArr = [[NSMutableArray alloc] init];
    for (NSString *infoStr in _crashStacks) {
        if (![_usefulCrashStacks containsObject:infoStr]) {
            [outputArr addObject:infoStr];
        } else {
            NSArray *infoComps = [infoStr componentsSeparatedByString:@"+ "];
            NSArray *infos = [infoStr componentsSeparatedByString:@"0x"];
            NSString *offset = infoComps.lastObject;
            if (offset) {
                NSString* methodName = [resultDic valueForKey:offset][@"symbol"];
                if (methodName) {
                    NSString *resultStr = [NSString stringWithFormat:@"%@ %@",infos.firstObject,methodName];
                    NSString *result = [resultStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
                    [outputArr addObject:result];
                } else {
                    [outputArr addObject:infoStr];
                }
            }
        }
    }
    NSString *outputer = [outputArr componentsJoinedByString:@"\n"];
    _resultView.string = [outputer copy];
    [_crashStacks removeAllObjects];
    [_usefulCrashStacks removeAllObjects];
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    
    // Drawing code here.
}

@end
