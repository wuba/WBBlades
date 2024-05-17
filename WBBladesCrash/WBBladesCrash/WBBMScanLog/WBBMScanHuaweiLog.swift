//
//  WBBMScanHuaweiLog.swift
//  WBBladesCrash
//
//  Created by zengqinglong on 2024/5/14.
//

import Foundation

class WBBMScanHuaweiLog{
    /**
     *  scan the bugly log with content
     *  @param content  the original content of Huawei log
     *  如：
     *  5 58tongcheng 0x000000010821d128 0x104440000 + 64868648
     *  每行都有6列，则是华为复制格式，第一列为序号，二列为进程名，三列为运行时的堆栈地址，四列为进程起始地址，五列为"+"，六列为运行时的偏移地址
     */
    class func scanHuaweiLog(content: String) -> WBBMLogModel?{
        let lines = content.split(separator: "\n")
        for singleline in lines {
            let tabs = singleline.split(separator: " ")
            if tabs.count != 6 {
                return nil
            }
        }
        let logModel = WBBMLogModel()
        logModel.logType = .HuaweiType
        return logModel
    }
}
