//
//  AnalyzeHeader.h
//  WBBladesForMac
//
//  Created by phs on 2019/12/27.
//  Copyright © 2019 邓竹立. All rights reserved.
//

#ifndef AnalyzeHeader_h
#define AnalyzeHeader_h

typedef NS_ENUM(NSInteger, AnalyzeType) {
    AnalyzeStaticLibrarySizeType = 0,//静态库体积分析
    AnalyzeAppUnusedClassType,//无用类检测
    AnalyzeAppCrashLogType,//无符号崩溃解析
};

#endif /* AnalyzeHeader_h */
