//
//  ViewController.swift
//  WBBladesCrashAnalyzeApp
//
//  Created by 朴惠姝 on 2021/4/22.
//

import Cocoa

open class WBBrightMirrorManager{
    open class func scanLog(logString: String) -> WBBMLogModel?{
       return WBBMScanLogManager.scanLog(logString: logString)
    }
    
    open class func downloadSymbol(logModel: WBBMLogModel, progressHandler:@escaping (Double)->Void, finishHandler:@escaping (String?)->Void) -> Void{
//        WBBMDownload.downloadSymbol(logModel: logModel) { (progress) in
//            progressHandler(progress)
//        }finishHandler: { (error) in
//            finishHandler(error)
//        }
    }
    
    open class func stopDownload(logModel: WBBMLogModel) -> Void{
//        WBBMDownload.stopDownloadSymbol(logModel: logModel)
    }
    
    open class func checkBuglyProcessName(logModel: WBBMLogModel){
        WBBMScanBuglyTool.checkBuglyProcessName(logModel: logModel)
    }
    
    open class func checkBuglyAnalzeReady(logModel: WBBMLogModel, symbolPath: String?,startAddress: String?, completionHandler: @escaping (_ ready: Bool) -> Void){
        WBBMScanBuglyTool.checkBuglyProcessStartAddress(logModel: logModel, symbolPath: symbolPath, startAddress: startAddress) { ready in
            completionHandler(ready)
        }
    }
    
    open class func startAnalyze(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ succeed: Bool,_ symbolReady: Bool, _ outputPath: String?) -> Void){
        //Whether it is light symbol
        WBBMLightSymbolTool.checkLightSymbolPath(path: symbolPath, processName: logModel.processName, uuid:logModel.processUUID) { (lightSymbolPath) in
            if let _ = lightSymbolPath{
                completionHandler(false,true,nil)
            }
            
            WBBMSymbolTool.startAnalyze(logModel: logModel, symbolPath: lightSymbolPath) { isComplete,fromDsym, resultLogModel in
                if isComplete == false {
                    completionHandler(false,false,nil)
                    return
                }
                if fromDsym != nil{
                    completionHandler(true,false,fromDsym)
                    return
                }
                
                WBBMOutputFile.outputResultFile(logResultModel: resultLogModel) { succeed, outputPath in
                    if succeed == false || outputPath == nil {
                        completionHandler(false,false,nil)
                    }else{
                        completionHandler(true,false,outputPath)
                    }
                    
                }
            }
        }
    }
    
    open class func stopAnalyze(logModel: WBBMLogModel) -> Void{
        WBBMSymbolTool.stopAnalyze(logModel: logModel)
    }
    
    open class func cleanAllCache() -> Void{
        WBBMOutputFile.cleanAllCache()
    }
}
