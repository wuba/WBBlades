//
//  ViewController.swift
//  WBBladesCrashAnalyzeApp
//
//  Created by wbblades on 2021/4/22.
//

import Cocoa

open class WBBladesCrashManager{
    /**
     *  scan log type and content
     *  @param logString  the original content of crash log
     */
    open class func scanLog(logString: String) -> WBBMLogModel?{
       return WBBMScanLogManager.scanLog(logString: logString)
    }

    /**
     *  whether the process name of bugly log corrects
     *  @param logModel  analyzed log model
     */
    open class func checkBuglyProcessName(logModel: WBBMLogModel){
        WBBMScanBuglyTool.checkBuglyProcessName(logModel: logModel)
    }
    
    /**
     *  check the necessary info of bugly log
     *  @param logModel         analyzed log model
     *  @param symbolPath       the absolute path of symbol table
     *  @param startAddress     the base address of process
     */
    open class func checkBuglyAnalzeReady(logModel: WBBMLogModel, symbolPath: String?,baseAddress: String?, completionHandler: @escaping (_ ready: Bool) -> Void){
        WBBMScanBuglyTool.checkBuglyProcessBaseAddress(logModel: logModel, symbolPath: symbolPath, baseAddress: baseAddress) { ready in
            completionHandler(ready)
        }
    }
    
    open class func checkSymbolPath(processName: String, uuid: String, _ completeHandler:@escaping (_ symbolPath: String?) -> Void ){
        WBBMLightSymbolTool.checkLightSymbolPath(path: nil, processName: processName, uuid: uuid) { lightSymbolPath in
            completeHandler(lightSymbolPath)
        }
    }
    
    /**
     *  analyzing start
     *  @param logModel              analyzed log model
     *  @param symbolPath            the absolute path of symbol table
     *  @param completionHandler     analyzing finish handler
     */
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
    
    /**
     *  stop analyzing
     *  @param logModel              analyzed log model
     */
    open class func stopAnalyze(logModel: WBBMLogModel) -> Void{
        WBBMSymbolTool.stopAnalyze(logModel: logModel)
    }
    
    /**
     *  clean all caches
     */
    open class func cleanAllCache() -> Void{
        WBBMOutputFile.cleanAllCache()
    }
}
