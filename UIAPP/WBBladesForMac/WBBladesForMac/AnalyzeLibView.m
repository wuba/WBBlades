//
//  AnalyzeLibView.m
//  WBBladesForMac
//
//  Created by phs on 2019/12/20.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#import "AnalyzeLibView.h"

@interface AnalyzeLibView()

@property (nonatomic, assign) AnalyzeType type;

@property (nonatomic,weak) NSTextView *excView;//可执行文件输入TextView
@property (nonatomic,weak) NSTextView *objFilesView;//静态库路径输入TextView
@property (nonatomic,weak) NSScrollView *scrollView;//输出进度ScrollView
@property (nonatomic,weak) NSTextView *consoleView;//输出进度TextView

@property (nonatomic,weak) NSButton *startBtn;//开始分析按钮
@property (nonatomic,weak) NSButton *stopBtn;//暂停分析按钮
@property (nonatomic,weak) NSButton *inFinderBtn;//打开结果文件夹按钮

@property (nonatomic,strong) NSMutableArray *taskArray;//任务列表
@property (nonatomic,assign) BOOL needStop;//是否被用户中断
@property (nonatomic,strong) dispatch_semaphore_t  sema;//信号

@end

@implementation AnalyzeLibView

- (instancetype)initWithFrame:(NSRect)frameRect type:(AnalyzeType)type {
    self = [super initWithFrame:frameRect];
    if (self) {
        _taskArray = [NSMutableArray array];
        _needStop = NO;
        self.type = type;
        [self prepareSubview];
        
    }
    return self;
}

-(void)dealloc {
    NSLog(@"dealloc");
}

/**
 * 初始化视图
 */
- (void)prepareSubview {
    CGFloat typeHeight = 0;
    if(self.type == AnalyzeAppUnusedClassType) {//无用类检测的特殊UI
        NSTextField *execLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0, 80, 36.0)];
        [self addSubview:execLabel];
        execLabel.font = [NSFont systemFontOfSize:14.0];
        execLabel.stringValue = @"可执行文件";
        execLabel.textColor = [NSColor blackColor];
        execLabel.editable = NO;
        execLabel.bezelStyle = NSBezelStyleTexturedSquare;
        execLabel.bordered = NO;
        execLabel.backgroundColor = [NSColor clearColor];
        
        NSScrollView *execScroll = [[NSScrollView alloc]initWithFrame:NSMakeRect(109.0, 440.0, 559.0, 30.0)];
        [self addSubview:execScroll];
        [execScroll setBorderType:NSLineBorder];
        execScroll.wantsLayer = YES;
        execScroll.layer.backgroundColor = [NSColor whiteColor].CGColor;
        execScroll.layer.borderWidth = 1.0;
        execScroll.layer.cornerRadius = 2.0;
        execScroll.layer.borderColor = [NSColor lightGrayColor].CGColor;
        
        NSTextView *excView = [[NSTextView alloc]initWithFrame:NSMakeRect(0.0, 0.0, 10000.0, 30.0)];
        excView.font = [NSFont systemFontOfSize:14.0];
        excView.textColor = [NSColor blackColor];
        execScroll.documentView = excView;
        excView.horizontallyResizable = YES;
        [excView.textContainer setWidthTracksTextView:NO];
        _excView = excView;
        
        NSTextField *excTipLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(109.0, 415.0, 580.0, 20.0)];
        [self addSubview:excTipLabel];
        excTipLabel.font = [NSFont systemFontOfSize:12.0];
        excTipLabel.stringValue = @"(必填)用于检测App中无用类，选择App可执行文件路径或ipa路径，如：\"/Users/a58/Desktop/xxx.app\"";
        excTipLabel.textColor = [NSColor grayColor];
        excTipLabel.editable = NO;
        excTipLabel.bezelStyle = NSBezelStyleTexturedSquare;
        excTipLabel.bordered = NO;
        excTipLabel.backgroundColor = [NSColor clearColor];
        
        NSButton *excBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 436.0, 105.0, 36.0)];
        [self addSubview:excBtn];
        excBtn.title = @"选择";
        excBtn.font = [NSFont systemFontOfSize:14.0];
        excBtn.target = self;
        excBtn.action = @selector(excuteFilePathBtnClicked:);
        excBtn.bordered = YES;
        excBtn.bezelStyle = NSBezelStyleRegularSquare;
        typeHeight = 53.0;
    }
    
    NSTextField *pathLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 428.0 - typeHeight, 80, 36.0)];
    [self addSubview:pathLabel];
    pathLabel.font = [NSFont systemFontOfSize:14.0];
    pathLabel.stringValue = @"静态库路径";
    pathLabel.textColor = [NSColor blackColor];
    pathLabel.editable = NO;
    pathLabel.bezelStyle = NSBezelStyleTexturedSquare;
    pathLabel.bordered = NO;
    pathLabel.backgroundColor = [NSColor clearColor];
    
    NSScrollView *textScroll = [[NSScrollView alloc]initWithFrame:NSMakeRect(109.0, 440.0 - typeHeight, 559.0, 30.0)];
    [self addSubview:textScroll];
    [textScroll setBorderType:NSLineBorder];
    textScroll.wantsLayer = YES;
    textScroll.layer.backgroundColor = [NSColor whiteColor].CGColor;
    textScroll.layer.borderWidth = 1.0;
    textScroll.layer.cornerRadius = 2.0;
    textScroll.layer.borderColor = [NSColor lightGrayColor].CGColor;
    
    NSTextView *textView = [[NSTextView alloc]initWithFrame:NSMakeRect(0.0, 0.0, 559.0, 30.0)];
    textView.font = [NSFont systemFontOfSize:14.0];
    textView.textColor = [NSColor blackColor];
    textScroll.documentView = textView;
    _objFilesView = textView;
    
    NSTextField *pathTipLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(109.0, 415.0 - typeHeight - 20, 559.0, 40.0)];
    [self addSubview:pathTipLabel];
    pathTipLabel.font = [NSFont systemFontOfSize:12.0];
    if (self.type == AnalyzeAppUnusedClassType) {//无用类检测的特殊UI
        pathTipLabel.stringValue = @"(非必填)获取该app中特定静态库(.a或.framework)的无用类。可选一个或多个静态库所在的目标文件夹，路径间以空格隔开。";
        pathTipLabel.maximumNumberOfLines = 0;
        
    } else {
        pathTipLabel.stringValue = @"选择或拖入一个或多个静态库（.a或.framework)或其所在的目标文件夹，路径间以空格隔开。";
    }
    pathTipLabel.textColor = [NSColor grayColor];
    pathTipLabel.editable = NO;
    pathTipLabel.bezelStyle = NSBezelStyleTexturedSquare;
    pathTipLabel.bordered = NO;
    pathTipLabel.backgroundColor = [NSColor clearColor];
    
    NSButton *pathBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 436.0 - typeHeight, 105.0, 36.0)];
    [self addSubview:pathBtn];
    pathBtn.title = @"选择文件夹";
    pathBtn.font = [NSFont systemFontOfSize:14.0];
    pathBtn.target = self;
    pathBtn.action = @selector(staticLibPathBtnClicked:);
    pathBtn.bordered = YES;
    pathBtn.bezelStyle = NSBezelStyleRegularSquare;
    
    NSTextField *progressLabel = [[NSTextField alloc]initWithFrame:NSMakeRect(25.0, 374.0 - typeHeight, 66, 36.0)];
    [self addSubview:progressLabel];
    progressLabel.font = [NSFont systemFontOfSize:14.0];
    progressLabel.stringValue = @"进度：";
    progressLabel.textColor = [NSColor blackColor];
    progressLabel.editable = NO;
    progressLabel.bordered = NO;
    progressLabel.backgroundColor = [NSColor clearColor];
    
    NSScrollView *scrollView = [[NSScrollView alloc]initWithFrame:NSMakeRect(30.0, 30.0, 638.0, 344.0 - typeHeight)];
    [self addSubview:scrollView];
    [scrollView setHasVerticalScroller:YES];
    [scrollView setBorderType:NSLineBorder];
    scrollView.wantsLayer = YES;
    scrollView.layer.backgroundColor = [NSColor whiteColor].CGColor;
    scrollView.layer.borderWidth = 1.0;
    scrollView.layer.cornerRadius = 2.0;
    scrollView.layer.borderColor = [NSColor lightGrayColor].CGColor;
    _scrollView = scrollView;
    
    NSTextView *consoleView = [[NSTextView alloc]initWithFrame:NSMakeRect(0.0, 0.0, scrollView.frame.size.width, scrollView.frame.size.height)];
    scrollView.documentView = consoleView;
    consoleView.font = [NSFont systemFontOfSize:14.0];
    consoleView.textColor = [NSColor blackColor];
    consoleView.editable = NO;
    _consoleView = consoleView;
    
    NSButton *startBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 339.0 - typeHeight, 105.0, 36.0)];
    [self addSubview:startBtn];
    startBtn.title = @"开始分析";
    startBtn.font = [NSFont systemFontOfSize:14.0];
    startBtn.target = self;
    startBtn.action = @selector(startBtnClicked:);
    startBtn.bordered = YES;
    startBtn.bezelStyle = NSBezelStyleRegularSquare;
    _startBtn = startBtn;
    
    NSButton *stopBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 276.0 - typeHeight, 105.0, 36.0)];
    [self addSubview:stopBtn];
    stopBtn.title = @"暂停分析";
    stopBtn.font = [NSFont systemFontOfSize:14.0];
    stopBtn.target = self;
    stopBtn.action = @selector(stopBtnClicked:);
    stopBtn.bordered = YES;
    stopBtn.bezelStyle = NSBezelStyleRegularSquare;
    stopBtn.enabled = NO;
    _stopBtn = stopBtn;
    
    NSButton *inFinderBtn = [[NSButton alloc]initWithFrame:NSMakeRect(693.0, 213.0 - typeHeight, 105.0, 36.0)];
    [self addSubview:inFinderBtn];
    inFinderBtn.title = @"打开文件夹";
    inFinderBtn.font = [NSFont systemFontOfSize:14.0];
    inFinderBtn.target = self;
    inFinderBtn.action = @selector(inFinderBtnClicked:);
    inFinderBtn.bordered = YES;
    inFinderBtn.bezelStyle = NSBezelStyleRegularSquare;
    inFinderBtn.enabled = NO;
    _inFinderBtn = inFinderBtn;
}

#pragma mark getter
/**
 * 信号
 */
- (dispatch_semaphore_t)sema {
    if (!_sema) {
        _sema = dispatch_semaphore_create(1);
    }
    return _sema;
}

#pragma mark 按钮响应事件
/**
 * 静态库大小检测，选择静态库路径
 */
- (void)staticLibPathBtnClicked:(id)sender {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt: @"打开"];
    openPanel.allowsMultipleSelection = YES;
    openPanel.canChooseDirectories = YES;
    openPanel.canChooseFiles = YES;
    openPanel.directoryURL = nil;
    openPanel.allowedFileTypes = @[@"a",@"framework"];
    
    __weak __typeof(self)weakSelf = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        if (returnCode == 1 && [openPanel URLs]) {
            NSMutableString *fileFolders = [NSMutableString stringWithString:@""];
            NSArray *array = [openPanel URLs];
            for (NSInteger idx = 0; idx<array.count; idx++) {
                NSURL *url = array[idx];
                NSString *urlString = [url.absoluteString substringFromIndex:7];//去掉file://
                NSString *string = @" ";
                if (idx == array.count - 1) {
                    string = @"";
                }
                [fileFolders appendFormat:@"%@%@",urlString,string];
            }
            weakSelf.objFilesView.string = [fileFolders copy];
        }
    }];
}

/**
 * 无用类检测，选择app可执行文件
 */
- (void)excuteFilePathBtnClicked:(id)sender {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setPrompt: @"选择app执行文件"];
    openPanel.allowsMultipleSelection = NO;
    openPanel.canChooseFiles = YES;
    openPanel.canChooseDirectories = NO;
    openPanel.directoryURL = nil;
    openPanel.allowedFileTypes = @[@"app",@"ipa"];
    
    __weak __typeof(self)weakSelf = self;
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        if (returnCode == 1 && [openPanel URLs]) {
            NSURL *url = [[openPanel URLs] firstObject];
            NSString *outputPath = [NSString stringWithFormat:@"%@",[url.absoluteString substringFromIndex:7]];
            weakSelf.excView.string = [outputPath stringByRemovingPercentEncoding];
        }
    }];
}

/**
 * 开始解析点击事件
 */
- (void)startBtnClicked:(id)sender {
    _startBtn.enabled = NO;
    _stopBtn.enabled = YES;
    _consoleView.string = @"";
    _needStop = NO;
    
    if (self.type == AnalyzeStaticLibrarySizeType) {//静态库体积分析
        [self analyzeLibSize];
    } else if (self.type == AnalyzeAppUnusedClassType) {//无用类检测
        [self analyzeUnusedClass];
    }
}

/**
 * 暂停解析点击事件
 */
- (void)stopBtnClicked:(id)sender {
    self.needStop = YES;
    _startBtn.enabled = YES;
    _stopBtn.enabled = NO;
    _inFinderBtn.enabled = NO;
    if (_sema) {
        dispatch_semaphore_signal(_sema);
    }
    if (self.taskArray && self.taskArray.count >0) {
        for (NSTask *task in self.taskArray) {
            [task terminate];
        }
        [self.taskArray removeAllObjects];
    }
    
    NSString *string = [NSString stringWithFormat:@"%@\n\n解析已中断。",self.consoleView.string];
    self.consoleView.string = string;
}

/**
 * 打开文件夹点击事件
 */
- (void)inFinderBtnClicked:(id)sender {
    NSURL *url = [self resultFileUrl];
    [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[url]];
}

/**
 * 关闭窗口
 */
- (void)closeWindow:(NSWindow *)window {
    [self stopBtnClicked:nil];
    [window orderOut:nil];
}

#pragma mark 静态库体积检测
/**
 * 静态库体积检测功能
 */
- (void)analyzeLibSize {
    if (self.objFilesView.string.length == 0) {
        [self stopAnalyzeAlertMessage:@"请输入目标路径，不能为空！" btnName:@"好的"];
        return;
    } else if (![self filePathValid:self.objFilesView.string] || [self includeChinese:self.objFilesView.string]) {
        [self stopAnalyzeAlertMessage:@"路径中不能包含中文或空格！" btnName:@"好的"];
        return;
    }
    
    NSArray *lines = [self.objFilesView.string componentsSeparatedByString:@"\n"];
    __block NSMutableArray *array = [[NSMutableArray alloc] init];
    [lines enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
        NSString *string = (NSString *)obj;
        NSArray *separateStrings = [string componentsSeparatedByString:@" "];
        [array addObjectsFromArray:separateStrings];
    }];

    if (array && array.count == 1) {
        array = (NSMutableArray *)[self.objFilesView.string componentsSeparatedByString:@" "];
    }
    
    if (_sema) {//若不是第一次开始，信号置为nil
        dispatch_semaphore_signal(_sema);
        _sema = nil;
    }
    
    dispatch_queue_t queue = dispatch_get_global_queue(0, 0);
    
    __weak __typeof(self)weakSelf = self;
    dispatch_async(queue, ^{
        for (NSInteger idx = 0; idx < array.count; idx++) {
            dispatch_semaphore_wait(weakSelf.sema, DISPATCH_TIME_FOREVER);
            if (weakSelf.needStop) {
                break;
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                __block NSString *string = weakSelf.consoleView.string;
                if (idx == 0) {
                    string = [NSString stringWithFormat:@"%@\n正在遍历 %@",string,array[idx]];
                    weakSelf.consoleView.string = string;
                }
                dispatch_async(queue, ^{
                    NSString *path = [[NSBundle mainBundle] pathForResource:@"WBBlades" ofType:@""];
                    NSTask *bladesTask = [[NSTask alloc] init];
                    [bladesTask setLaunchPath:path];
                    //执行命令参数：type(1) 静态库所在文件夹路径(array[idx])
                    [bladesTask setArguments:[NSArray arrayWithObjects:@"1", array[idx], nil]];
                    NSLog(@"the index is: %ld", idx);
                    [bladesTask launch];
                    [weakSelf.taskArray addObject:bladesTask];
                    [bladesTask waitUntilExit];//同步执行
                    
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [bladesTask terminate];
                        if (weakSelf && !weakSelf.needStop) {
                            if (idx <array.count - 1) {
                                string = [NSString stringWithFormat:@"%@\n正在遍历 %@",string,array[idx+1]];
                                weakSelf.consoleView.string = string;
                            }
                            if (idx == array.count - 1) {
                                string = [NSString stringWithFormat:@"%@\n\n遍历完毕，可点击打开文件夹查看结果数据，将保存到WBBladesResult.plist中。\n",string];
                                weakSelf.consoleView.string = string;
                                weakSelf.startBtn.enabled = YES;
                                weakSelf.stopBtn.enabled = NO;
                                weakSelf.inFinderBtn.enabled = YES;
                                
                                [self openResultFile];
                            }
                            dispatch_semaphore_signal(weakSelf.sema);
                        }
                    });
                });
            });
        }
    });
}

#pragma mark 无用类检测
/**
 * 无用类检测功能
 */
- (void)analyzeUnusedClass {
    if (self.excView.string.length == 0) {
        [self stopAnalyzeAlertMessage:@"请输入App执行文件，不能为空!" btnName:@"好的"];
        return;
    }else if (![[NSFileManager defaultManager] fileExistsAtPath:self.excView.string]) {
        [self stopAnalyzeAlertMessage:@"未找到有效的可执行文件，请输入正确的可执行文件！" btnName:@"好的"];
        return;
    }else if (![self filePathValid:self.excView.string]|| [self includeChinese:self.excView.string]){
        [self stopAnalyzeAlertMessage:@"路径中不能包含中文或空格！" btnName:@"好的"];
        return;
    }
    NSString *string = [self.objFilesView.string stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    NSMutableArray *array = [NSMutableArray arrayWithArray:[string componentsSeparatedByString:@" "]];
    if (!array || array.count == 0) {
        array = [NSMutableArray array];
    }
    //执行命令参数：type(2) 可执行文件路径(self.excView.string) 静态库路径(/Users/a58/xxx)
    [array insertObjects:@[@"2",self.excView.string] atIndexes:[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(0, 2)]];
    self.consoleView.string = @"开始解析，请耐心等待";
    __weak __typeof(self)weakSelf = self;
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *path = [[NSBundle mainBundle] pathForResource:@"WBBlades" ofType:@""];
        NSTask *bladesTask = [[NSTask alloc] init];
        [bladesTask setLaunchPath:path];
        [bladesTask setArguments:[array copy]];
        [bladesTask launch];
        [weakSelf.taskArray addObject:bladesTask];
        [bladesTask waitUntilExit];//同步执行
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weakSelf.needStop) {
                weakSelf.consoleView.string = [NSString stringWithFormat:@"%@\n解析完成，可点击打开文件夹查看结果数据，将保存到WBBladesClass.plist中",weakSelf.consoleView.string];
                weakSelf.startBtn.enabled = YES;
                weakSelf.stopBtn.enabled = NO;
                weakSelf.inFinderBtn.enabled = YES;
                [self openResultFile];
            }
        });
    });
}

#pragma mark Tools
/**
 * 错误弹框
 */
- (void)stopAnalyzeAlertMessage:(NSString*)msg btnName:(NSString *)btnName {
    NSAlert *alert = [[NSAlert alloc]init];
    [alert addButtonWithTitle:btnName];
    [alert setMessageText:msg];
    __weak __typeof(self)weakSelf = self;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse returnCode) {
        weakSelf.startBtn.enabled = YES;
        weakSelf.stopBtn.enabled = NO;
        weakSelf.consoleView.string = @"";
        weakSelf.needStop = YES;
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

/**
 * 打开解析结果文件
 */
- (void)openResultFile {
    NSURL *url = [self resultFileUrl];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

/**
 * 存放解析结果的文件路径
 */
- (NSURL *)resultFileUrl {
    NSString *fileName = @"";
    if (self.type == AnalyzeStaticLibrarySizeType) {
        fileName = @"/WBBladesResult.plist";
    } else if (self.type == AnalyzeAppUnusedClassType) {
        fileName = @"/WBBladesClass.plist";
    }
    
    NSString *deskTop = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory, NSUserDomainMask, YES) firstObject];
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"file://%@%@",deskTop,fileName]];
    return url;
}

/**
 * 检测文件路径是否有效
 */
- (BOOL)filePathValid:(NSString *)filePath {
    NSArray *lines = [filePath componentsSeparatedByString:@"\n"];
    NSMutableArray *files = [NSMutableArray array];
    [lines enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
        NSString *string = (NSString *)obj;
        NSArray *separaStrings = [string componentsSeparatedByString:@" "];
        [files addObjectsFromArray:separaStrings];
    }];
    
    for (NSString *path in files) {
        NSString *filePathWithoutSpace = [path stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (![[NSFileManager defaultManager] fileExistsAtPath:filePathWithoutSpace]) {
            return NO;
        }
    }
    return YES;
}

@end
