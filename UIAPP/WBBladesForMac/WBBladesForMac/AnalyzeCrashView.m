//
//  AnalyzeCrashView.m
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeCrashView.h"

@interface AnalyzeCrashView()

@property (nonatomic,weak) NSTextView *exeFileView;//可执行文件输入TextView
@property (nonatomic,weak) NSTextView *crashStackView;//崩溃堆栈TextView
@property (nonatomic,weak) NSTextView *resultView;//输出结果TextView
@property (nonatomic,weak) NSButton *startButton;//开始分析按钮
@property (nonatomic,weak) NSButton *importBtn;//导入日志文件

@property (nonatomic,strong) NSMutableArray *crashStacks;//所有堆栈信息
@property (nonatomic,strong) NSMutableArray *usefulCrashStacks;//需要解析的堆栈
@property (nonatomic,strong) NSTask *bladeTask;//任务

@end

@implementation AnalyzeCrashView

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        [self prepareSubview];
    }
    return self;
}

/**
* 初始化视图
*/
- (void)prepareSubview {
    _crashStacks = [[NSMutableArray alloc] init];
    _usefulCrashStacks = [[NSMutableArray alloc] init];
    
    NSTextField *exeLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0, 80, 36.0)];
    [self addSubview:exeLabel];
    exeLabel.font = [NSFont systemFontOfSize:14.0];
    exeLabel.stringValue = @"可执行文件";
    exeLabel.alignment = NSTextAlignmentCenter;
    exeLabel.textColor = [NSColor blackColor];
    exeLabel.editable = NO;
    exeLabel.bezelStyle = NSBezelStyleTexturedSquare;
    exeLabel.bordered = NO;
    exeLabel.backgroundColor = [NSColor clearColor];
    
    NSScrollView *exeScroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(109.0, 440.0, 559.0, 30.0)];
    [self addSubview:exeScroll];
    [exeScroll setBorderType:NSLineBorder];
    exeScroll.wantsLayer = YES;
    exeScroll.layer.backgroundColor = [NSColor whiteColor].CGColor;
    exeScroll.layer.borderWidth = 1.0;
    exeScroll.layer.cornerRadius = 2.0;
    exeScroll.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSTextView *textView = [[NSTextView alloc]initWithFrame:NSMakeRect(0.0, 0.0, 10000.0, 30.0)];
    exeScroll.documentView = textView;
    textView.horizontallyResizable = YES;
    [textView.textContainer setWidthTracksTextView:NO];
    textView.font = [NSFont systemFontOfSize:14.0];
    textView.textColor = [NSColor blackColor];
    textView.wantsLayer = YES;
    _exeFileView = textView;
    
    NSButton *ipaPreviewBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 436.0, 105.0, 36.0)];
    [self addSubview:ipaPreviewBtn];
    ipaPreviewBtn.title = @"选择文件";
    ipaPreviewBtn.font = [NSFont systemFontOfSize:14.0];
    ipaPreviewBtn.target = self;
    ipaPreviewBtn.action = @selector(ipaPreviewBtnClicked:);
    ipaPreviewBtn.bordered = YES;
    ipaPreviewBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextField *excTipLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(109.0, 399.0, 559.0, 40.0)];
    excTipLabel.maximumNumberOfLines = 0;
    [self addSubview:excTipLabel];
    excTipLabel.alignment = NSTextAlignmentLeft;
    excTipLabel.font = [NSFont systemFontOfSize:13.0];
    excTipLabel.stringValue = @"(必填)请选择或拖入一个App可执行文件或ipa包文件路径，如：\"/Users/a58/Desktop/xxx.app\"";
    excTipLabel.textColor = [NSColor grayColor];
    excTipLabel.editable = NO;
    excTipLabel.bezelStyle = NSBezelStyleTexturedSquare;
    excTipLabel.bordered = NO;
    excTipLabel.backgroundColor = [NSColor clearColor];
    
    NSTextField *crashOriLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 364.0, 200.0, 38.0)];
    [self addSubview:crashOriLabel];
    crashOriLabel.font = [NSFont systemFontOfSize:14.0];
    crashOriLabel.stringValue = @"粘贴需要解析的堆栈";
    crashOriLabel.textColor = [NSColor blackColor];
    crashOriLabel.editable = NO;
    crashOriLabel.bordered = NO;
    crashOriLabel.backgroundColor = [NSColor clearColor];
    
    NSButton *importBtn = [[NSButton alloc]initWithFrame:NSMakeRect(550.0, 376.0, 120.0, 36.0)];
    [self addSubview:importBtn];
    importBtn.title = @"导入崩溃日志";
    importBtn.font = [NSFont systemFontOfSize:14.0];
    importBtn.target = self;
    importBtn.action = @selector(importBtnClicked:);
    importBtn.bordered = YES;
    importBtn.bezelStyle = NSBezelStyleRegularSquare;
    _importBtn = importBtn;
    
    NSButton *startBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 376.0, 105.0, 36.0)];
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

#pragma mark 响应事件
/**
* 选择出现崩溃的app可执行文件
*/
- (void)ipaPreviewBtnClicked:(id)sender {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt:@"选择可执行文件"];
    openPanel.allowsMultipleSelection = NO;
    openPanel.canChooseFiles = YES;
    openPanel.directoryURL = nil;
    [openPanel setAllowedFileTypes:[NSArray arrayWithObjects:@"", @"app", nil]];
    
    __weak __typeof(self) weakself = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        
        if (returnCode == 1 && [openPanel URLs]) {
            NSURL *url = [[openPanel URLs] firstObject];
            NSString *filePath = [NSString stringWithFormat:@"%@",[url.absoluteString substringFromIndex:7]];
            weakself.exeFileView.string = [filePath stringByRemovingPercentEncoding];
            //weakself.ipaFileView.editable = NO;
        }
    }];
}

/**
* 选择崩溃日志
*/
- (void)importBtnClicked:(id)sender {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt:@"选择崩溃日志文件"];
    openPanel.allowsMultipleSelection = NO;
    openPanel.canChooseFiles = YES;
    [openPanel setAllowedFileTypes:@[@"ips",@"crash",@"synced",@"beta",@"txt"]];
    
    __weak __typeof(self) weakself = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        if (returnCode == 1 && [openPanel URLs]) {
            NSURL *url = [[openPanel URLs] firstObject];
            NSString *logString = [weakself importCrashLogStack:url];
            weakself.crashStackView.string = logString;
        }
    }];
}

/**
* 开始解析
*/
- (void)startBtnClicked:(id)sender {
    
    [_crashStacks removeAllObjects];
    
    _resultView.string = @"";
    _startButton.enabled = NO;
    _crashStackView.editable = NO;
    _importBtn.enabled = NO;
    NSURL *fileUrl = [NSURL fileURLWithPath:_exeFileView.string];
    NSArray *tmp = [_exeFileView.string componentsSeparatedByString:@"."];
    NSString *fileType = @"";
    NSString *fileName = @"";
    if ([tmp count] == 2) {
        fileType = [tmp lastObject];
        NSString *filePath = [tmp firstObject];
        fileName = [filePath componentsSeparatedByString:@"/"].lastObject;
    }
    NSData *fileData = [NSMutableData dataWithContentsOfURL:fileUrl];
    if (!fileData && ![fileType isEqualToString:@"app"]) {
        [self stopAnalyzeAlertMessage:@"请选择或拖入一个可执行文件" btnName:@"好的"];
        return;
    }else if ([self.exeFileView.string containsString:@" "] || [self includeChinese:self.exeFileView.string]){
        [self stopAnalyzeAlertMessage:@"路径中不能包含中文或空格！" btnName:@"好的"];
        return;
    }
    
    // 获得可执行文件的名称
    NSString *execName = [_exeFileView.string componentsSeparatedByString:@"/"].lastObject;
    
    // 获得此app的崩溃地址
    NSArray *crashInfoLines = [_crashStackView.string componentsSeparatedByString:@"\n"];
    NSMutableArray *crashOffsets = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < crashInfoLines.count; i++) {
        
        NSString *crashLine = crashInfoLines[i];
        NSArray *compos = [crashLine componentsSeparatedByString:@" "];
        if (compos.count > 2) {
            if ([crashLine containsString:execName] || [crashLine containsString:fileName]) {
                NSString *offset = compos.lastObject;
                if (offset.longLongValue) {
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
        [alert setMessageText:@"请粘贴App对应的崩溃堆栈"];
        [alert beginSheetModalForWindow:self.window completionHandler:nil];
        _startButton.enabled = YES;
        _crashStackView.editable = YES;
        _importBtn.enabled = YES;
        return;
    }
}

#pragma mark Analyze
/**
* 根据偏移地址解析
*/
- (void)analyzeCrashFromOffsets:(NSString*)offsets {
    _resultView.string = @"解析中，请稍候";
    
    __weak typeof(self) weakSelf = self;
    NSString *inputFile = _exeFileView.string;
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *path = [[NSBundle mainBundle] pathForResource:@"WBBlades" ofType:@""];
        NSTask *bladesTask = [[NSTask alloc] init];
        weakSelf.bladeTask = bladesTask;
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
            weakSelf.bladeTask = nil;
            [weakSelf outputResults:resultsDic];
        });
    });
}

/**
* 崩溃解析结果
*/
- (void)outputResults:(NSDictionary*)resultDic {
    _startButton.enabled = YES;
    _crashStackView.editable = YES;
    _importBtn.enabled = YES;
    NSMutableArray *outputArr = [[NSMutableArray alloc] init];
    for (NSString *infoStr in _crashStacks) {
        if (![_usefulCrashStacks containsObject:infoStr]) {
            [outputArr addObject:infoStr];
        } else {
            NSArray *infoComps = [infoStr componentsSeparatedByString:@" "];
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
    
    NSString *directoryPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory, NSUserDomainMask, YES) firstObject];
    
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy_MM_dd_HH_mm_ss"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Beijing"]];
    NSDate *date = [NSDate date];
    NSString *currentTimeString = [dateFormatter stringFromDate:date];
    
    NSString *outputerPath = [directoryPath stringByAppendingPathComponent:[NSString stringWithFormat:@"WBBladesCrash_%@.txt",currentTimeString]];
    
    [outputer writeToFile:outputerPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    [self openResultFile:currentTimeString];
}

/**
* 打开崩溃解析结果文件
*/
- (void)openResultFile:(NSString *)currentTimeString{
    NSString *fileName = [NSString stringWithFormat:@"/WBBladesCrash_%@.txt",currentTimeString];
    NSString *desktop = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory, NSUserDomainMask, YES) firstObject];
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"file://%@%@", desktop, fileName]];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

/**
* 关闭窗口
*/
- (void)closeWindow:(NSWindow *)window {
    if (!self.bladeTask) {
        [window orderOut:nil];
        return;
    }
    NSAlert *alert = [[NSAlert alloc]init];
    [alert addButtonWithTitle:@"退出"];
    [alert addButtonWithTitle:@"取消"];
    [alert setMessageText:@"崩溃日志正在解析中，是否确定退出？"];
    [alert setAlertStyle:NSAlertFirstButtonReturn];
    __weak __typeof(self)weakSelf = self;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        if (returnCode == NSAlertFirstButtonReturn) {
            [weakSelf.bladeTask terminate];
            weakSelf.bladeTask = nil;
            [window orderOut:nil];
        }
    }];
}

#pragma mark Tools
/**
* 获取崩溃堆栈
*/
- (NSString *)importCrashLogStack:(NSURL*)url {
    NSString *dataString = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:NULL];
    NSArray *lines = [dataString componentsSeparatedByString:@"\n"];
    
    NSMutableArray *array = [NSMutableArray array];
    NSString *binaryAddress = @"";
    NSString *backtraceAddress = @"";
    NSUInteger backtraceIndex = -1;
    BOOL found = NO;
    for (NSInteger i = 0; i<lines.count; i++) {
        NSString *line = lines[i];
        if ([line hasPrefix:@"Last Exception"]) {//找到第一个Thread
            found = YES;
        }else if(found && ([line hasPrefix:@"(0x"] && [lines[i-1]  hasPrefix:@"Last Exception"])){
            backtraceAddress = line;
            backtraceIndex = i;
        }else if(found && ([line hasPrefix:@"Binary"] || [line hasPrefix:@"0x"])){
            if (i+1 < lines.count) {//Binary Image：的下一行
                binaryAddress = lines[i+1];
            }
            break;
        }
        [array addObject:line];
    }
    
    //特殊处理Last Exception Backtrace中包含多个地址的情况
    if (backtraceAddress && backtraceAddress.length > 0 && binaryAddress && binaryAddress.length >0) {
        NSArray *addressLines = [self obtainLastExceptionCrashModels:backtraceAddress
                                                       binaryAddress:binaryAddress];
        if (addressLines && addressLines.count > 0) {
            [array replaceObjectAtIndex:backtraceIndex withObject:@""];
            [array insertObjects:addressLines atIndexes:[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(backtraceIndex, addressLines.count)]];
        }
    }
    
    NSMutableString *resultString = [NSMutableString string];
    for (NSString *line in array) {
        [resultString appendString:[NSString stringWithFormat:@"%@\n",line]];
    }
    return [resultString copy];
}

/**
* 从Last Exception Backtrace中获取与当前进程的地址，并转为Model
*/
- (NSArray<NSString*>*)obtainLastExceptionCrashModels:(NSString *)string
                                        binaryAddress:(NSString*)between {
    NSMutableArray *array = [NSMutableArray array];
    
    NSArray *processArray = [between componentsSeparatedByString:@" "];
    if (processArray.count < 4) {
        return nil;
    }
    NSString *processStart = [processArray firstObject];//当前进程的起始地址
    NSInteger startNum = [self numberWithHexString:[processStart stringByReplacingOccurrencesOfString:@"0x" withString:@""]];
    NSString *processEnd = processArray[2];//当前进程的结束地址
    NSString *processName = processArray[3];//当前进程名
    
    NSString *newString = [string stringByReplacingOccurrencesOfString:@"(" withString:@""];
    newString = [newString stringByReplacingOccurrencesOfString:@")" withString:@""];
    NSArray *crashAddresses = [newString componentsSeparatedByString:@" "];//获取所有地址
    if (crashAddresses && crashAddresses.count > 0) {
        for (NSInteger i = 0; i<crashAddresses.count; i++) {
            NSString *string = crashAddresses[i];
            //当前地址小于结束地址，大于起始地址
            if (([string compare:processEnd] == NSOrderedAscending) && ([string compare:processStart] == NSOrderedDescending)) {
                NSInteger stringNum = [self numberWithHexString:[string stringByReplacingOccurrencesOfString:@"0x" withString:@""]];
                NSInteger offsetNum = stringNum - startNum;
                NSString *stack = [NSString stringWithFormat:@"%li %@ %lu",i,processName,offsetNum];
                [array addObject:stack];
            } else {
                [array addObject:string];
            }
        }
    }
    
    return [array copy];
}

/**
* 十六进制字符串转数字
*/
- (NSInteger)numberWithHexString:(NSString *)hexString {
    const char *hexChar = [hexString cStringUsingEncoding:NSUTF8StringEncoding];
    int hexNumber;
    sscanf(hexChar, "%x", &hexNumber);
    return (NSInteger)hexNumber;
}

/**
* 错误弹框
*/
- (void)stopAnalyzeAlertMessage:(NSString*)msg btnName:(NSString *)btnName {
    NSAlert *alert = [[NSAlert alloc]init];
    [alert addButtonWithTitle:btnName];
    [alert setMessageText:msg];
    __weak __typeof(self)weakSelf = self;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        weakSelf.startButton.enabled = YES;
        weakSelf.crashStackView.editable = YES;
        weakSelf.importBtn.enabled = YES;
    }];
}

/**
* 判断是否包含中文
*/
- (BOOL)includeChinese:(NSString *)string
{
    for(int i=0; i< [string length];i++)
    {
        int a = [string characterAtIndex:i];
        if( a >0x4e00&& a <0x9fff){
            return YES;
        }
    }
    return NO;
}

@end
