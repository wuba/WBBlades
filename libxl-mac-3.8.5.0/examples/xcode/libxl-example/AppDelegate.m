//
//  AppDelegate.m
//  libxl-example
//

#import "AppDelegate.h"
#include "LibXL/libxl.h"

@interface ExcelModel : NSObject

@property(nonatomic,copy)NSString* pod;

@property(nonatomic,copy)NSString* codeSize;

@property(nonatomic,copy)NSString* resourceSize;

@property(nonatomic,copy)NSString* totalSize;

@property(nonatomic,copy)NSString* lastTotalSize;

@property(nonatomic,copy)NSString* increment;


@end

@implementation ExcelModel

@end



@implementation AppDelegate

@synthesize window;

- (id)init
{
	[NSApp setDelegate:self];
	return self;
}

-(BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
	return YES;
}

- (void)dealloc
{
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
}

- (IBAction)createExcel:(id)sender
{
    NSString *lastPath = self.lastPath.stringValue;
    NSString *currentPath = self.currentPath.stringValue;
    
    if (lastPath.length == 0|| currentPath.length == 0) {
        return;
    }
    
    NSMutableDictionary *lastData = [[NSDictionary dictionaryWithContentsOfFile:lastPath] mutableCopy];
    NSMutableDictionary *currentData = [[NSDictionary dictionaryWithContentsOfFile:currentPath] mutableCopy];

    if (!lastData|| !currentData) {
        return;
    }

    FontHandle titleFont;
    FontHandle redFont;
    FontHandle greenFont;
    FormatHandle headerFormat;
    FormatHandle descriptionFormat;
    FormatHandle redFormat;
    FormatHandle greenFormat;
    SheetHandle sheet;
    BookHandle book;
    
    book = xlCreateXMLBook();
    titleFont = xlBookAddFont(book, 0);
    redFont = xlBookAddFont(book, 0);
    greenFont = xlBookAddFont(book, 0);

    headerFormat = xlBookAddFormat(book, 0);
    xlFormatSetAlignH(headerFormat, ALIGNH_CENTER);
    xlFormatSetBorder(headerFormat, BORDERSTYLE_THIN);
    xlFormatSetFillPattern(headerFormat, FILLPATTERN_SOLID);
    xlFormatSetPatternForegroundColor(headerFormat, COLOR_TAN);
    
    descriptionFormat = xlBookAddFormat(book, 0);
    xlFormatSetAlignH(descriptionFormat, ALIGNH_CENTER);
    xlFormatSetBorderLeft(descriptionFormat, BORDERSTYLE_THIN);
    xlFormatSetBorderRight(descriptionFormat, BORDERSTYLE_THIN);
    xlFormatSetBorderTop(descriptionFormat, BORDERSTYLE_THIN);
    xlFormatSetBorderBottom(descriptionFormat, BORDERSTYLE_THIN);
    xlFormatSetAlignH(descriptionFormat, ALIGNH_CENTER);
    xlFormatSetAlignV(descriptionFormat, ALIGNV_CENTER);

    
    redFormat = xlBookAddFormat(book, 0);
    xlFormatSetAlignH(redFormat, ALIGNH_CENTER);
    xlFormatSetBorderLeft(redFormat, BORDERSTYLE_THIN);
    xlFontSetColorA(redFont, COLOR_RED);
    xlFormatSetFontA(redFormat, redFont);
    xlFormatSetBorderTop(redFormat, BORDERSTYLE_THIN);
    xlFormatSetBorderBottom(redFormat, BORDERSTYLE_THIN);
    xlFormatSetAlignH(redFormat, ALIGNH_CENTER);
    xlFormatSetAlignV(redFormat, ALIGNV_CENTER);
    
    greenFormat = xlBookAddFormat(book, 0);
    xlFormatSetAlignH(greenFormat, ALIGNH_CENTER);
    xlFormatSetBorderLeft(greenFormat, BORDERSTYLE_THIN);
    xlFontSetColorA(greenFont, COLOR_GREEN);
    xlFormatSetFontA(greenFormat, greenFont);
    xlFormatSetBorderTop(greenFormat, BORDERSTYLE_THIN);
    xlFormatSetBorderBottom(greenFormat, BORDERSTYLE_THIN);
    xlFormatSetAlignH(greenFormat, ALIGNH_CENTER);
    xlFormatSetAlignV(greenFormat, ALIGNV_CENTER);
    
    
    NSDateFormatter *format = [[NSDateFormatter alloc] init];
    format.dateFormat = @"yyyyMMdd-HHmmss";
    NSString *time = [format stringFromDate:[NSDate date]];
    NSString *title = [NSString stringWithFormat:@"版本对照-%@",time];
    sheet = xlBookAddSheet(book,[title cStringUsingEncoding:NSUTF8StringEncoding], 0);
    
    //总计
    NSMutableDictionary *oriLastData = [[NSDictionary dictionaryWithContentsOfFile:lastPath] mutableCopy];
    NSMutableDictionary *oriCurrentData = [[NSDictionary dictionaryWithContentsOfFile:currentPath] mutableCopy];
    __block CGFloat lResSize = 0;
    __block CGFloat lTotalSize = 0;
    
    CGFloat cCodeSize = 0;
    __block CGFloat cResSize = 0;
    __block CGFloat cTotalSize = 0;
    
    [oriLastData enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        
        NSDictionary *dic = (NSDictionary *)obj;
        NSString *str = dic[@"total"];
        lTotalSize += [[str stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
        str = dic[@"resource"];
        lResSize += [[str stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    }];
    
    [oriCurrentData enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        
        NSDictionary *dic = (NSDictionary *)obj;
        NSString *str = dic[@"total"];
        cTotalSize += [[str stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
        str = dic[@"resource"];
        cResSize += [[str stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    }];
    
    
    if(sheet)
    {
        const char *header0 = [@"Module" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header1 = [@"Pod" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header2 = [@"last total" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header3 = [@"total" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header4 = [@"increment" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header5 = [@"Module total" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header6 = [@"Module increment" cStringUsingEncoding:NSUTF8StringEncoding];
        const char *header7 = [@"Module percent" cStringUsingEncoding:NSUTF8StringEncoding];

        xlSheetWriteStr(sheet, 2, 1, header0, headerFormat);
        xlSheetWriteStr(sheet, 2, 2, header1, headerFormat);
        xlSheetWriteStr(sheet, 2, 3, header2, headerFormat);
        xlSheetWriteStr(sheet, 2, 4, header3, headerFormat);
        xlSheetWriteStr(sheet, 2, 5, header4, headerFormat);
        xlSheetWriteStr(sheet, 2, 6, header5, headerFormat);
        xlSheetWriteStr(sheet, 2, 7, header6, headerFormat);
        xlSheetWriteStr(sheet, 2, 8, header7, headerFormat);

        NSArray *json = @[
                               
                               @{@"zufang":@[@"HouseCommonBusiness",@"House"]},
                               @{ @"ershou":@[@"SecondHandGoods"]},
                               @{@"ershouche":@[@"UsedCar"]},
  @{@"anjuke":@[@"WBAIFFrameworks",@"WBAJKCommonBusiness",@"WBAJKUserModule",@"WBAnjuke",@"WBAnjukeMoudle",@"WBZiXun",@"WBNewHouseModule"]},
                               @{@"zhaopin":@[@"WBJob"]},
                               @{@"huangye":@[@"YellowPage"]},
                               @{@"pinche":@[@"WBPinche"]},
                               @{@"buluo":@[@"WBTribe"]},
                               @{@"shouye":@[@"WBMainPage"]},
                               @{@"gerenzhongxin":@[@"WBUserCenter"]},
                               @{@"IM":@[@"WBIM"]},
                               @{@"fabu":@[@"WBPublishInfo"]},
                               @{@"faxian":@[@"WBDiscovery"]},
                               @{@"RN":@[@"WBReactNativeLibrary"]},
                               @{@"jichufuwu":@[@"WBServicePlatform"]},
                               @{@"jichuVC":@[@"WBBasicArchitecture"]},
                               @{@"tongyongliebiao":@[@"WBCommonNativeList"]},
                               @{@"tongyongxiangqing":@[@"WBCommonNativeDetail"]},
                               @{@"laoliebiao":@[@"WBOldListDetail"]},
                               @{@"passport":@[@"WBLNLoginFramework"]},
                               @{@"3rd":@[@"WBAPP3rd",@"wb3rdcomponent",@"WBPublic3rd"]},
                               ];
        
        
        __block int i = 1;
        for (NSDictionary *module in json) {
            
            //模块
            NSString *moduleName = [[module allKeys] firstObject];
            NSArray *pods = (NSArray *)module[moduleName];
            xlSheetWriteStr(sheet, i+2, 1, [moduleName cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
            
            CGFloat moduleIncrement = 0;
            CGFloat moduleTotal = 0;
            int start = i+2;
            for (int j=0; j<pods.count; j++) {
                
                //pod
                NSString *podName = pods[j];
                xlSheetWriteStr(sheet, i+2, 2, [podName cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
                
                ExcelModel *excel = [self getExcelModelWithPod:podName lastData:lastData currentData:currentData];
                
                //上版本大小
                xlSheetWriteStr(sheet, i+2, 3, [excel.lastTotalSize cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
                //当前版本大小
                xlSheetWriteStr(sheet, i+2, 4, [excel.totalSize cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
                
                CGFloat increment = [excel.increment floatValue];
                moduleIncrement += increment;
                
                //当前版本增量
                if (increment >0 ) {
                    NSString *str = [@"+" stringByAppendingString:excel.increment];
                    xlSheetWriteStr(sheet, i+2, 5, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
                }else if (increment == 0){
                    xlSheetWriteStr(sheet, i+2, 5, [excel.increment cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
                    
                }else{
                    xlSheetWriteStr(sheet, i+2, 5, [excel.increment cStringUsingEncoding:NSUTF8StringEncoding], greenFormat);
                }
                
                moduleTotal += [excel.totalSize floatValue];
                
                i ++;
            }
            //当前模块大小
            xlSheetWriteStr(sheet, start, 6, [[NSString stringWithFormat:@"%.1f",moduleTotal] cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
            //当前模块增量
            if (moduleIncrement >0 ) {
                NSString *str = [@"+" stringByAppendingString:[NSString stringWithFormat:@"%.1f",moduleIncrement]];
                xlSheetWriteStr(sheet, start, 7, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
            }else if (moduleIncrement == 0){
                NSString *str = [NSString stringWithFormat:@"%.1f",moduleIncrement];
                xlSheetWriteStr(sheet, start, 7, [str cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
            }else{
                NSString *str = [NSString stringWithFormat:@"%.1f",moduleIncrement];
                xlSheetWriteStr(sheet,start, 7, [str cStringUsingEncoding:NSUTF8StringEncoding], greenFormat);
            }
            
            //当前模块占比
            CGFloat percent = moduleTotal/cTotalSize;
            if (percent >= 0.1) {
                NSString *str = [NSString stringWithFormat:@"%.1f%%",percent*100];
                xlSheetWriteStr(sheet,start, 8, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
            }else{
                NSString *str = [NSString stringWithFormat:@"%.1f%%",percent*100];
                xlSheetWriteStr(sheet, start, 8, [str cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
            }
            
            //调整行宽、行高
            xlSheetSetCol(sheet, 1, 1, 12, 0, 0);
            xlSheetSetCol(sheet, 2, 2, 25, 0, 0);
            xlSheetSetCol(sheet, 3, 8, 12, 0, 0);
            
            //合并单元格
            xlSheetSetMergeA(sheet,start, i+1, 1, 1);
            xlSheetSetMergeA(sheet,start, i+1, 6, 6);
            xlSheetSetMergeA(sheet,start, i+1, 7, 7);
            xlSheetSetMergeA(sheet,start, i+1, 8, 8);
        }
        
        //其他pod
        ExcelModel *excel = [self getExcelModelWithPod:@"others" lastData:lastData currentData:currentData];
        xlSheetWriteStr(sheet, i+2, 1, "others", descriptionFormat);
        xlSheetWriteStr(sheet, i+2, 2, "all", descriptionFormat);
        xlSheetWriteStr(sheet, i+2, 3, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+2, 4, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+2, 5, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+2, 6, [excel.totalSize cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
        CGFloat increment = [excel.increment floatValue];
        if (increment >0 ) {
            NSString *str = [@"+" stringByAppendingString:excel.increment];
            xlSheetWriteStr(sheet, i+2, 7, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
        }else if (increment == 0){
            xlSheetWriteStr(sheet, i+2, 7, [excel.increment cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
        }else{
            xlSheetWriteStr(sheet, i+2, 7, [excel.increment cStringUsingEncoding:NSUTF8StringEncoding], greenFormat);
        }
        //模块占比
        CGFloat percent = [excel.totalSize floatValue]/cTotalSize;
        if (percent >= 0.1) {
            NSString *str = [NSString stringWithFormat:@"%.1f%%",percent*100];
            xlSheetWriteStr(sheet, i+2, 8, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
        }else{
            NSString *str = [NSString stringWithFormat:@"%.1f%%",percent*100];
            xlSheetWriteStr(sheet, i+2, 8, [str cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
        }
        
        
        cCodeSize = cTotalSize - cResSize;
        xlSheetWriteStr(sheet, i+3, 1, "zongji", descriptionFormat);
        xlSheetWriteStr(sheet, i+3, 2, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+3, 3, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+3, 4, " ", descriptionFormat);
        xlSheetWriteStr(sheet, i+3, 5, " ", descriptionFormat);

        xlSheetWriteStr(sheet, i+3, 6, [[NSString stringWithFormat:@"%.1f",cTotalSize] cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
        increment = cTotalSize - lTotalSize;
        NSString *incrementStr = [NSString stringWithFormat:@"%.1f",increment];
        if (increment >0 ) {
            NSString *str = [@"+" stringByAppendingString:incrementStr];
            xlSheetWriteStr(sheet, i+3, 7, [str cStringUsingEncoding:NSUTF8StringEncoding], redFormat);
        }else if (increment == 0){
            xlSheetWriteStr(sheet, i+3, 7, [incrementStr cStringUsingEncoding:NSUTF8StringEncoding], descriptionFormat);
        }else{
            xlSheetWriteStr(sheet, i+3, 7, [incrementStr cStringUsingEncoding:NSUTF8StringEncoding], greenFormat);
        }
        xlSheetWriteStr(sheet, i+3, 8, "100%", redFormat);
    }
    
    NSString *name = [NSString stringWithFormat:@"%@.xlsx",title];
    NSString *documentPath =
    [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    NSString *filename = [documentPath stringByAppendingPathComponent:name];
    
    xlBookSave(book, [filename UTF8String]);
    
    xlBookRelease(book);
    
    [[NSWorkspace sharedWorkspace] openFile:filename];
}


- (ExcelModel *)getExcelModelWithPod:(NSString*)podName lastData:(NSMutableDictionary*)lastData currentData:(NSMutableDictionary *)currentData{
    
    if ([podName isEqualToString:@"others"]) {
        
        NSMutableSet *keys = [NSMutableSet set];
        [keys addObjectsFromArray:lastData.allKeys];
        [keys addObjectsFromArray:currentData.allKeys];
        
        CGFloat lastResourceSize = 0.0;
        CGFloat lastTotalSize = 0 ;
        __block CGFloat lastCodeSize = 0;
        
        CGFloat curResourceSize = 0.0;
        CGFloat curTotalSize = 0.0;
        __block CGFloat curCodeSize = 0;
        
        for (NSString *key in keys) {

            NSMutableDictionary *tmp = [lastData[key] mutableCopy];
            NSString *lastResource = lastData[key][@"resource"];
            NSString *lastTotal = lastData[key][@"total"];
            lastResourceSize += [[lastResource stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            lastTotalSize += [[lastTotal stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            
            [tmp removeObjectForKey:@"resource"];
            [tmp removeObjectForKey:@"total"];
            
            [tmp enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
                NSString *size = (NSString *)obj;
                lastCodeSize += [[size stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            }];
            
            tmp = [currentData[key] mutableCopy];
            NSString *currentResource = currentData[key][@"resource"];
            NSString *currentTotal = currentData[key][@"total"];
            curResourceSize += [[currentResource stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            curTotalSize += [[currentTotal stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            
            [tmp removeObjectForKey:@"resource"];
            [tmp removeObjectForKey:@"total"];
            
            [tmp enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
                NSString *size = (NSString *)obj;
                curCodeSize += [[size stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
            }];
            
            [lastData removeObjectForKey:key];
            [currentData removeObjectForKey:key];
            
        }
        ExcelModel *model = [ExcelModel new];
        model.codeSize = [NSString stringWithFormat:@"%.1f",curCodeSize];
        model.resourceSize = [NSString stringWithFormat:@"%.1f",curResourceSize];
        model.totalSize = [NSString stringWithFormat:@"%.1f",curTotalSize];
        model.lastTotalSize = [NSString stringWithFormat:@"%.1f",lastTotalSize];
        model.increment = [NSString stringWithFormat:@"%.1f",curTotalSize - lastTotalSize];
        return model;
    }
    
    NSString *pod = podName;
    NSString *key = [NSString stringWithFormat:@"%@Lib",pod];

    NSMutableDictionary *tmp = [lastData[key] mutableCopy];
    NSString *lastTotal = lastData[key][@"total"];
    CGFloat lastTotalSize = [[lastTotal stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    __block CGFloat lastCodeSize = 0;
    
    [tmp removeObjectForKey:@"resource"];
    [tmp removeObjectForKey:@"total"];
    
    [tmp enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *size = (NSString *)obj;
        lastCodeSize += [[size stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    }];
    
     tmp = [currentData[key] mutableCopy];
    NSString *currentResource = currentData[key][@"resource"];
    NSString *currentTotal = currentData[key][@"total"];
    CGFloat curResourceSize = [[currentResource stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    CGFloat curTotalSize = [[currentTotal stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    __block CGFloat curCodeSize = 0;
    
    [tmp removeObjectForKey:@"resource"];
    [tmp removeObjectForKey:@"total"];
    
    [tmp enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *size = (NSString *)obj;
        curCodeSize += [[size stringByReplacingOccurrencesOfString:@" MB" withString:@""] floatValue];
    }];
    
    [lastData removeObjectForKey:key];
    [currentData removeObjectForKey:key];

    ExcelModel *model = [[ExcelModel alloc] init];
    model.codeSize = [NSString stringWithFormat:@"%.1f",curCodeSize];
    model.resourceSize = [NSString stringWithFormat:@"%.1f",curResourceSize];
    model.totalSize = [NSString stringWithFormat:@"%.1f",curTotalSize];
    model.increment = [NSString stringWithFormat:@"%.1f",curTotalSize - lastTotalSize];
    model.lastTotalSize = [NSString stringWithFormat:@"%.1f",lastTotalSize];
    return model;
}


@end
