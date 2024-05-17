//
//  WBBMScanLogManager.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/4/27.
//

import Foundation

class WBBMScanLogManager {
    /**
     *  scan log type and content
     *  @param logString  the original content of crash log
     */
    class func scanLog(logString: String) -> WBBMLogModel?{
       if logString.count == 0 {
           return nil
       }
       
       //scan system crash log
       if let logModel: WBBMLogModel = WBBMScanSystemLog.scanSystemLog(content: logString) {
           return logModel
       }
    
       //scan bugly crash log
       if let logModel: WBBMLogModel = WBBMScanBuglyLog.scanBuglyLog(content: logString) {
           return logModel
       }
        //scan huawei crash log
        if let logModel: WBBMLogModel = WBBMScanHuaweiLog.scanHuaweiLog(content: logString) {
            return logModel
        }
       return nil
   }
}
