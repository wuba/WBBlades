//
//  WBBMScanBuglyLog.swift
//  WBBrightMirror
//
//  Created by 朴惠姝 on 2021/5/26.
//

import Foundation

class WBBMScanBuglyLog{
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
        
        for suchline in lines {
            if index%3 == 0 {
                let suchIndex = Int(suchline)
                if suchIndex == nil {
                    isBuglyLog = false
                    break
                }
                stackModel = WBBMStackModel()
                stackModel.squence = suchIndex ?? 0
            }else if index%3 == 1 {
                let array = suchline.split(separator: " ")
                if array.count == 0 || array.count != 1 {
                    isBuglyLog = false
                    break
                }
                stackModel.process = String(array[0])
            }else if index%3 == 2 {
                let array = suchline.split(separator: " ")
                if array.count > 1 {
                    let adr = String(array[0])
                    if !adr.hasPrefix("0x") {
                        isBuglyLog = false
                        break
                    }
                }
                stackModel.address = String(array[0])
                stackModel.offset =  String(array.last ?? "")
                stackModel.analyzeResult = "\(stackModel.squence) \(stackModel.process)\t\(suchline)"
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
            if stackModel.process.contains("???") {
                stackModel.process = logModel.processName
                stackModel.analyzeResult = stackModel.analyzeResult.replacingOccurrences(of: "???", with: logModel.processName)
            }
        }
    }
    class func checkBuglyProcessStartAddress(logModel: WBBMLogModel, symbolPath: String?,startAddress: String?, completionHandler: @escaping (_ ready: Bool) -> Void) {
        if let adr = startAddress{
            if adr.count > 0 {
                let demical = WBBMScanLogTool.hexToDecimal(hex: adr)
                setBuglyStartAddress(logModel: logModel,demicalAddress: demical)
                completionHandler(true)
                return
            }
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
                if stackModel.process == "???" {
                    stackModel.process = logModel.processName
                }
                if stackModel.process == logModel.processName {
                    let suchArray = stackModel.analyzeResult.split(separator: " ")
                    if suchArray.count > 3 {
                        var tmpStackAddress = stackModel.address.trimmingCharacters(in: .whitespaces)

                        if tmpStackAddress.count > 12 {
                            let startI = tmpStackAddress.index(tmpStackAddress.startIndex, offsetBy: 9);
                            tmpStackAddress = "0x\(tmpStackAddress[startI..<tmpStackAddress.endIndex])"
                        }
                        let sAdr = Int(WBBMScanLogTool.hexToDecimal(hex: tmpStackAddress )) ?? 0
                        let sOff = Int(stackModel.offset) ?? 0
                        stackAddress = sAdr - sOff
                        functionName = String(suchArray[2])
                        break
                    }
                }
            }
            
            guard let resultModel =  WBBMSymbolTool.searchFunctionInfo(functionName: functionName, logModel: logModel, symbolPath: symbolPath) else{
                completionHandler(false)
                return
            }
            
            let funcStartAddress = Int(WBBMScanLogTool.hexToDecimal(hex: resultModel.start)) ?? 0
            self.setBuglyStartAddress(logModel: logModel,demicalAddress: "\(stackAddress - funcStartAddress)")
            DispatchQueue.main.async{
                completionHandler(true)
            }
        }
    }
    
    class func setBuglyStartAddress(logModel: WBBMLogModel,demicalAddress: String){
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
            if stackModel.process == logModel.processName {
                stackModel.processStartAddress = demicalAddress
            }
        }
    }
}
