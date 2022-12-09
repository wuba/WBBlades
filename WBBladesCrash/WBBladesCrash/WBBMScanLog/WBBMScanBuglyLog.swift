//
//  WBBMScanBuglyLog.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/5/26.
//

import Foundation

class WBBMScanBuglyLog{
    /**
     *  scan the bugly log with content
     *  @param content  the original content of bugly log
     */
    class func scanBuglyLog(content: String) -> WBBMLogModel?{
        let lines = content.split(separator: "\n")
        
        let logModel = WBBMLogModel()
        logModel.logType = .BuglyType
        logModel.processName = ""
        logModel.processUUID = ""
        logModel.version = ""
        
        let detailModel = WBBMLogDetailModel()
        let threadInfo = WBBMThreadInfoModel()
        var stackArray: Array<WBBMStackModel> = Array()
        
        var index = 0
        var isBuglyLog = true
        
        var stackModel: WBBMStackModel = WBBMStackModel()
        
        for singleline in lines {
            if index%3 == 0 {//first line is squence
                let singleIndex = Int(singleline)
                if singleIndex == nil {
                    isBuglyLog = false
                    break
                }
                stackModel = WBBMStackModel()
                stackModel.squence = singleIndex ?? 0
            }else if index%3 == 1 {//second line is library name
                let array = singleline.split(separator: " ")
                if array.count == 0 || array.count != 1 {
                    isBuglyLog = false
                    break
                }
                stackModel.library = String(array[0])
            }else if index%3 == 2 {//last line
                let array = singleline.split(separator: " ")
                if array.count > 1 {
                    let adr = String(array[0])
                    if !adr.hasPrefix("0x") {
                        isBuglyLog = false
                        break
                    }
                }
                stackModel.address = String(array[0])
                stackModel.offset =  String(array.last ?? "")
                stackModel.analyzeResult = "\(stackModel.squence) \(stackModel.library)\t\(singleline)"
                stackArray.append(stackModel)
            }
            index += 1
        }
        
        if isBuglyLog {
            threadInfo.stackArray = stackArray
            detailModel.threadInfoArray = [threadInfo]
            logModel.detailModel = detailModel
            return logModel
        }
        return nil
    }
}

class WBBMScanBuglyTool{
    /**
     *  whether the process name of bugly log corrects
     *  @param logModel  analyzed log model
     */
    class func checkBuglyProcessName(logModel: WBBMLogModel){
        let detailModel = logModel.detailModel
        guard let threadInfoArray = detailModel?.threadInfoArray else{
            return
        }
        
        let threadInfo = threadInfoArray[0]
        let stackArray: Array<WBBMStackModel> = threadInfo.stackArray
        guard stackArray.count > 0 else {
            return
        }
        
        for stackModel in stackArray {
            if stackModel.library.contains("???") {
                stackModel.library = logModel.processName
                stackModel.analyzeResult = stackModel.analyzeResult.replacingOccurrences(of: "???", with: logModel.processName)
            }
        }
    }
    
    /**
     *  check the necessary info of bugly log
     *  @param logModel         analyzed log model
     *  @param symbolPath       the absolute path of symbol table
     *  @param startAddress     the base address of process
     */
    class func checkBuglyProcessBaseAddress(logModel: WBBMLogModel, symbolPath: String?,baseAddress: String?, completionHandler: @escaping (_ ready: Bool) -> Void) {
        if let adr = baseAddress, adr.count > 0{
            let demical = WBBMScanLogTool.hexToDecimal(hex: adr)
            setBuglyBaseAddress(logModel: logModel,demicalAddress: demical)
            completionHandler(true)
            return
        }
        
        DispatchQueue.global().async{
            let detailModel = logModel.detailModel
            guard let threadInfoArray = detailModel?.threadInfoArray else{
                return
            }
            
            let threadInfo = threadInfoArray[0]
            let stackArray: Array<WBBMStackModel> = threadInfo.stackArray
            guard stackArray.count > 0 else {
                return
            }
            
            var stackAddress = 0
            var functionName = ""
            for stackModel in stackArray.reversed() {
                if stackModel.library == "???" {
                    stackModel.library = logModel.processName
                }
                if stackModel.library == logModel.processName {
                    let singleArray = stackModel.analyzeResult.split(separator: " ")
                    if singleArray.count > 3 {
                        var tmpStackAddress = stackModel.address.trimmingCharacters(in: .whitespaces)

                        if tmpStackAddress.count > 12 {//correct the high address
                            let startI = tmpStackAddress.index(tmpStackAddress.startIndex, offsetBy: 9);
                            tmpStackAddress = "0x\(tmpStackAddress[startI..<tmpStackAddress.endIndex])"
                        }
                        let sAdr = Int(WBBMScanLogTool.hexToDecimal(hex: tmpStackAddress )) ?? 0
                        let sOff = Int(stackModel.offset) ?? 0
                        stackAddress = sAdr - sOff
                        functionName = String(singleArray[2])
                        break
                    }
                }
            }
            
            //Find the offset address by the function name
            guard let resultModel =  WBBMSymbolTool.searchFunctionInfo(functionName: functionName, logModel: logModel, symbolPath: symbolPath) else{
                completionHandler(false)
                return
            }
            
            let funcStartAddress = Int(WBBMScanLogTool.hexToDecimal(hex: resultModel.start)) ?? 0
            self.setBuglyBaseAddress(logModel: logModel,demicalAddress: "\(stackAddress - funcStartAddress)")
            DispatchQueue.main.async{
                completionHandler(true)
            }
        }
    }
    
    /**
     *  set the bugly base address
     *  @param logModel           analyzed log model
     *  @param demicalAddress     the base address of process in demical
     */
    class func setBuglyBaseAddress(logModel: WBBMLogModel,demicalAddress: String){
        let detailModel = logModel.detailModel
        guard let threadInfoArray = detailModel?.threadInfoArray else{
            return
        }
        
        let threadInfo = threadInfoArray[0]
        let stackArray: Array<WBBMStackModel> = threadInfo.stackArray
        guard stackArray.count > 0 else {
            return
        }
        
        for stackModel in stackArray {
            if stackModel.library == logModel.processName {
                stackModel.libraryStartAddress = demicalAddress
            }
        }
    }
}
