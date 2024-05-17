//
//  WBExeShell.m
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2024/5/15.
//

#import "WBExeShell.h"

@implementation WBExeShell
+ (NSString *)crashAnalysisLogContent:(NSString *)logContent dSYMPath:(NSString *)dSYMPath ProcessName:(NSString *)proName
{
    NSString *userName = NSUserName();
    NSString *logFilePath = [NSString stringWithFormat:@"/Users/%@/Desktop/temp.txt", userName];
    NSError *error;
    [logContent writeToFile:logFilePath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"写入文件时发生错误: %@", error);
    }
    // 调用自定义shell脚本
    // 创建一个NSTask对象
    NSTask *task = [[NSTask alloc] init];
    // 设置任务的拉 launhPath（shell 脚本路径）
    [task setLaunchPath:@"/bin/sh"];
    // 创建一个包含脚本路径的数组
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    NSString *shellPath = [NSString stringWithFormat:@"%@/Contents/Resources/crashAnalysis.sh", appPath];
    NSArray *arguments = @[shellPath, proName, logFilePath, dSYMPath];
    // 设置脚本参数
    task.arguments = arguments;
    // 指定标准输出和错误
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;
    // 启动任务
    [task launch];
    // 读取输出
    NSFileHandle *file = [pipe fileHandleForReading];
    NSData *data = [file readDataToEndOfFile];
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    // 打印输出
    NSLog(@"%@", output);
    // 等待任务完成
    [task waitUntilExit];
    // 获取退出状态
    int status = [task terminationStatus];
    // 打印退出状态
    NSLog(@"脚本执行结束状态：%d", status);
    // 删除崩溃日志中间文件
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL success = [fileManager removeItemAtPath:logFilePath error:&error];
    if (success) {
        NSLog(@"成功删除了中间日志文件");
    } else {
        NSLog(@"删除文件时发生错误: %@", [error localizedDescription]);
    }
    return output;
}


@end
