//
//  WBBMScanSystemCrashTool.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/4/25.
//

import Foundation

class WBBMScanSystemLog {
    /**
     *  check system crash log
     *  @param content      crash log contents
     */
    class func scanSystemLog(content: String) -> WBBMLogModel?{
        
        let logModel = WBBMLogModel.init()
        
        var detailContent = content;
        
        //standard format has header info.
        if content.hasPrefix("{"){
            var braceCount = 0
            var appInfo = String.init()
            for char in content {
                appInfo.append(char)
                if char == "{" { braceCount += 1}
                else if char == "}" { braceCount -= 1}
                if braceCount == 0 {break}
            }
            
            let jsonData: Data = appInfo.data(using: .utf8) ?? Data.init()
            let appInfoDic: Dictionary<String,Any> = try! JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers) as? Dictionary<String,Any> ?? [:]
            
            if appInfoDic.keys.count == 0 {
                return nil
            }
            
            //obtain bug type
            let bug_type = appInfoDic["bug_type"] as? String ?? ""
            logModel.logType = WBBMLogType(rawValue: bug_type) ?? WBBMLogType(rawValue: "")!
            logModel.processName = appInfoDic["app_name"] as? String ?? ""
            logModel.processUUID = appInfoDic["slice_uuid"] as? String ?? ""
            logModel.version = appInfoDic["app_version"] as? String ?? ""
            
            let start = content.index(content.startIndex, offsetBy: appInfo.count)
            detailContent = String.init(content[start..<content.endIndex])
        }else if content.hasPrefix("Incident Identifier:"){//hasn't header info & prefix of Incident Identifier:
            var lineIndex = 0
            let lines: Array<Substring> = content.split(separator: Character.init("\n"))
            let logHeaderDic = WBBMScanSystemLogTool.checkLogHeader(lines:lines,&lineIndex,endLine: "Triggered by Thread")
            let processName = String((logHeaderDic["Process"] as? String ?? "").split(separator: " ").first ?? "")
            let processDic = WBBMScanSystemLogTool.scanSystemLibraryBinaryUUID(lines: lines, processIdentifier:(logHeaderDic["Identifier"] as? String ?? ""), processName: processName)
            logModel.logType = .SystemDemoCrash
            logModel.processName = processName
            logModel.processUUID = processDic[processName] ?? ""
            logModel.version = logHeaderDic["Version"] as? String ?? ""
        }else if content.hasPrefix("Date/Time:"){//hasn't header info & prefix of Date/Time:
            var lineIndex = 0
            let lines: Array<Substring> = content.split(separator: Character.init("\n"))
            let logHeaderDic = WBBMScanSystemLogTool.checkLogHeader(lines:lines,&lineIndex,endLine: "Heaviest stack for the target process:")
            let processName = String((logHeaderDic["Command"] as? String ?? "").split(separator: " ").first ?? "")
            let processDic = WBBMScanSystemLogTool.scanSystemLibraryBinaryUUID(lines: lines, processIdentifier:(logHeaderDic["Identifier"] as? String ?? ""), processName: processName)
            logModel.logType = .SystemWakeUp
            logModel.processName = processName
            logModel.processUUID = processDic[processName] ?? ""
            logModel.version = logHeaderDic["Version"] as? String ?? ""
        }else{//not a system crash log
            return nil
        }
        
        //crash log type
        if logModel.logType == .SystemCrash || logModel.logType == .SystemDemoCrash {
            let detailModel = scanSystemCrashLog(content: detailContent)
            logModel.detailModel = detailModel
            if logModel.detailModel.threadInfoArray.count ==  0 {
                return nil
            }
        }else if logModel.logType == .SystemWakeUp{
            let detailModel = scanSystemWakeupLog(content: detailContent)
            logModel.detailModel = detailModel
        }else if logModel.logType == .SystemNewCrash{//iOS14+ json crash type
            let detailModel = scanSystemNewCrashLog(content: detailContent, uuid: logModel.processUUID)
            logModel.detailModel = detailModel
        }
        
        return logModel
    }
    
    //MARK: -
    //MARK: System Crash Log(bug_type:109)
    class func scanSystemCrashLog(content: String) -> WBBMLogDetailModel {
        var lineIndex = 0
        let lines: Array<Substring> = content.split(separator: Character.init("\n"))
        let logHeaderDic = WBBMScanSystemLogTool.checkLogHeader(lines:lines,&lineIndex,endLine: "Triggered by Thread")
        
        let logDetailModel = WBBMLogDetailModel.init()
        var headerLogString = ""
        for index in 0..<lineIndex {
            headerLogString.append("\(String(lines[index]))\n")
        }
        logDetailModel.headerLogString = headerLogString
        logDetailModel.identifier = logHeaderDic["Identifier"] as? String ?? ""
        logDetailModel.hardwareModel = logHeaderDic["Hardware Model"] as? String ?? ""
        let processName = String((logHeaderDic["Process"] as? String ?? "").split(separator: " ").first ?? "")
        logDetailModel.processName = processName
        logDetailModel.crashTime = logHeaderDic["Date/Time"] as? String ?? ""
        logDetailModel.launchTime = logHeaderDic["Launch Time"] as? String ?? ""
        logDetailModel.osVersion = logHeaderDic["OS Version"] as? String ?? ""
        logDetailModel.exceptionType = logHeaderDic["Exception Type"] as? String ?? ""
        logDetailModel.terminationReason = logHeaderDic["Termination Reason"] as? String ?? ""
        logDetailModel.terminationDescription = logHeaderDic["Termination Description"] as? String ?? ""
        logDetailModel.triggeredThread = logHeaderDic["Triggered by Thread"] as? String ?? ""
        
        //scan the base address&end address of all libraries
        let libraryDic = WBBMScanSystemLogTool.scanSystemLibraryAddress(lines: lines, processIdentifier: logDetailModel.identifier, processName: processName)
        if libraryDic.keys.count == 0 {
            logDetailModel.threadInfoArray = []
            return logDetailModel
        }
        
        //crash stack
        var threadInfoArray: Array<WBBMThreadInfoModel> = Array.init()
        
        //check last exception backtrace
        if let backtraceInfo = scanSystemCrashAbortedLog(lines: lines, &lineIndex,processName: processName, libraryDic: libraryDic) {
            threadInfoArray.append(backtraceInfo)
        }
        
        //scan single thread stack
        var singleThread: Array<String> = Array.init()
        var singleThreadNum = 0
        for index in lineIndex..<lines.count {
            let singleline = lines[index]
            //current thread's end line is next thread's first line
            if WBBMScanSystemLogTool.checkSystemCrashEndLine(line: String(singleline)){
                if let threadInfo = scanSystemCrashProcessLog(lines: singleThread, processName: processName, libraryDic: libraryDic) as WBBMThreadInfoModel? {
                    threadInfoArray.append(threadInfo)
                }
                singleThread.removeAll()
                break
            }
            
            if singleline.count == 0 || singleline.hasPrefix("Thread \(singleThreadNum+1) name:") || singleline.hasPrefix("Thread \(singleThreadNum+1)"){
                singleThreadNum += 1
                if let threadInfo = scanSystemCrashProcessLog(lines: singleThread, processName: processName, libraryDic: libraryDic) as WBBMThreadInfoModel? {
                    threadInfoArray.append(threadInfo)
                }
                singleThread.removeAll()
            }
            
            singleThread.append(String(singleline))
        }
        
        logDetailModel.threadInfoArray = threadInfoArray
        return logDetailModel
    }
    
    //System crash log has "Last Exception Backtrace"
    class func scanSystemCrashAbortedLog(lines: Array<Substring>, _ lastIndex: UnsafeMutablePointer<Int>, processName: String, libraryDic: Dictionary<String,Array<String>>) -> WBBMThreadInfoModel?{
        if lines[lastIndex.pointee].hasPrefix("Thread") || libraryDic.keys.count == 0 {
            return nil
        }
        
        let abortedString = "Last Exception Backtrace:"
        var foundedBacktrace = false
        for index in lastIndex.pointee..<lines.count {
            let singleline = lines[index]
            if singleline.hasPrefix(abortedString) {
                foundedBacktrace = true
                lastIndex.pointee = index+2
                break
            }
        }
        
        if !foundedBacktrace {
            return nil
        }
        
        let threadInfo = WBBMThreadInfoModel.init()
        threadInfo.threadName = abortedString
        threadInfo.threadSequence = ""
        var threadInfoArray: Array<WBBMStackModel> = Array.init()
        
        if String(lines[lastIndex.pointee - 1]).hasPrefix("(") {
            let backtraceString = String(lines[lastIndex.pointee - 1]).replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "")
            let backtraceArray = backtraceString.split(separator: " ")
            var threadIndex = 0
            for singleAdr in backtraceArray {
                let singleValue = Int(WBBMScanLogTool.hexToDecimal(hex: String(singleAdr))) ?? 0
                let stackModel = WBBMStackModel.init()
                stackModel.squence = threadIndex
                stackModel.address = String(singleAdr)
                for (key,adrArray) in libraryDic {
                    let startAdr = Int(String(adrArray[0])) ?? 0
                    let endAdr = Int(String(adrArray[1])) ?? 0
                    if singleValue > startAdr && singleValue < endAdr {
                        stackModel.library = String(key)
                        stackModel.libraryStartAddress = String(startAdr)
                        stackModel.libraryEndAddress = String(endAdr)
                        break
                    }
                }
                if stackModel.library.count == 0 {
                    stackModel.library = processName
                    let adrArray = libraryDic[processName] ?? []
                    let startAdr = Int(String(adrArray[0])) ?? 0
                    let endAdr = Int(String(adrArray[1])) ?? 0
                    stackModel.libraryStartAddress = String(startAdr)
                    stackModel.libraryEndAddress = String(endAdr)
                }
                originalResult(stackModel: stackModel)
                threadInfoArray.append(stackModel)
                threadIndex += 1
            }
        }else{
            let startIndex = lastIndex.pointee - 1
            for index in startIndex..<lines.count {
                let singleline = lines[index]
                if singleline.hasPrefix("Thread ") {
                    lastIndex.pointee = index
                    break
                }
                let singleArray = singleline.split(separator: Character.init(" "))
                if singleArray.count > 5 {
                    let stackModel = WBBMStackModel.init()
                    stackModel.squence = Int(singleArray[0]) ?? 0
                    var library = String(singleArray[1])
                    if library.contains("???"){
                        library = processName
                    }
                    stackModel.library = library
                    stackModel.address = String(singleArray[2])
                    stackModel.libraryStartAddress = (libraryDic[stackModel.library] ?? []).first ?? ""
                    stackModel.libraryEndAddress = (libraryDic[stackModel.library] ?? []).last ?? ""
                    stackModel.offset = String(singleArray.last ?? "")
                    stackModel.analyzeResult = String(singleline)
                    threadInfoArray.append(stackModel)
                }
            }
        }
        
        threadInfo.stackArray = threadInfoArray
        return threadInfo
    }
    
    //scan every thread stacks
    class func scanSystemCrashProcessLog(lines: Array<String>,processName: String, libraryDic:Dictionary<String, Array<String>>) -> WBBMThreadInfoModel {
        let threadInfoModel = WBBMThreadInfoModel.init()
        
        let firstLine = lines.first ?? ""
        let lineArray = firstLine.split(separator: Character.init(":"))
        let threadTitle = lineArray.first ?? ""
        let threadSqu = threadTitle.replacingOccurrences(of: "name", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
        threadInfoModel.threadSequence = threadSqu
        threadInfoModel.threadName = firstLine.replacingOccurrences(of: threadTitle, with: "").replacingOccurrences(of: ":", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
        
        var stacks: Array<WBBMStackModel> = Array.init()
        var startIndex = 1
        if lines[1].hasPrefix("Thread") {
            startIndex = 2;
        }
        for index in startIndex..<lines.count {
            let singleLine = lines[index]
            let singleArray = singleLine.split(separator: Character.init(" "))
            if singleArray.count > 5 {
                let stackModel = WBBMStackModel.init()
                stackModel.squence = Int(singleArray[0]) ?? 0
                var process = String(singleArray[1])
                if process.contains("???"){
                    process = processName
                }
                stackModel.library = process
                stackModel.address = String(singleArray[2]).replacingOccurrences(of: "\t", with: "")
                stackModel.libraryStartAddress = (libraryDic[stackModel.library] ?? []).first ?? ""
                stackModel.libraryEndAddress = (libraryDic[stackModel.library] ?? []).last ?? ""
                stackModel.offset = String(singleArray.last ?? "")
                stackModel.analyzeResult = singleLine
                stacks.append(stackModel)
            }
        }
        threadInfoModel.stackArray = stacks
        
        return threadInfoModel
    }
    
    //MARK: -
    //MARK: System Wake Up(bug_type:142)
    class func scanSystemWakeupLog(content: String) -> WBBMLogDetailModel {
        var lineIndex = 0
        let lines: Array<Substring> = content.split(separator: Character.init("\n"))
        let logHeaderDic = WBBMScanSystemLogTool.checkLogHeader(lines:lines,&lineIndex,endLine: "Heaviest stack for the target process:")
        
        let logDetailModel = WBBMLogDetailModel.init()
        var headerLogString = ""
        for index in 0..<lineIndex {
            headerLogString.append("\(String(lines[index]))\n")
        }
        logDetailModel.headerLogString = headerLogString
        logDetailModel.identifier = logHeaderDic["Identifier"] as? String ?? ""
        logDetailModel.hardwareModel = logHeaderDic["Hardware Model"] as? String ?? ""
        let processName = logHeaderDic["Command"] as? String ?? ""
        logDetailModel.processName = processName
        logDetailModel.crashTime = logHeaderDic["Date/Time"] as? String ?? ""
        logDetailModel.launchTime = logHeaderDic["Launch Time"] as? String ?? ""
        logDetailModel.osVersion = logHeaderDic["OS Version"] as? String ?? ""
        logDetailModel.exceptionType = logHeaderDic["Event"] as? String ?? ""
        logDetailModel.terminationReason = logHeaderDic["Wakeups"] as? String ?? ""
        let cpuActives = logHeaderDic["Active cpus"] ?? ""
        logDetailModel.terminationDescription = "Active CPUs are \(cpuActives)"
        logDetailModel.triggeredThread = ""
        
        //scan the base address&end address of all libraries
        let libraryDic = WBBMScanSystemLogTool.scanSystemLibraryAddress(lines: lines, processIdentifier: logDetailModel.identifier, processName: processName)
        if libraryDic.keys.count == 0 {
            logDetailModel.threadInfoArray = []
            return logDetailModel
        }
        
        //scan heaviest thread
        var singleThread: Array<String> = Array.init()
        for index in lineIndex..<lines.count {
            let singleline = String(lines[index])
            if WBBMScanSystemLogTool.checkSystemCrashEndLine(line: singleline) {
                break
            }
            singleThread.append(singleline)
        }
        let threadInfo = scanSystemWakeupProcessLog(lines: singleThread, processName:logDetailModel.processName, libraryDic:libraryDic)
        logDetailModel.threadInfoArray = [threadInfo]
        return logDetailModel
    }
    
    //scan wake up log
    class func scanSystemWakeupProcessLog(lines: Array<String>, processName: String, libraryDic:Dictionary<String,Array<String>>) -> WBBMThreadInfoModel {
        
        var stacks: Array<WBBMStackModel> = Array.init()
        for singleline in lines {
            let singleArray = singleline.split(separator: Character.init(" "))
            if singleArray.count > 5 {
                let stackModel = WBBMStackModel.init()
                stackModel.squence = Int(singleArray[0]) ?? 0
                var library = String(singleArray[2]).replacingOccurrences(of: "(", with: "")
                if library.contains("???"){
                    library = processName
                }
                stackModel.library = library
                stackModel.address = String(singleArray[5]).trimmingCharacters(in: CharacterSet.init(charactersIn: "[]"))
                stackModel.libraryStartAddress = (libraryDic[stackModel.library] ?? []).first ?? ""
                stackModel.libraryEndAddress = (libraryDic[stackModel.library] ?? []).last ?? ""
                stackModel.offset = String(singleArray.last ?? "").replacingOccurrences(of: ")", with: "")
                stackModel.analyzeResult = singleline;
                stacks.append(stackModel)
            }
        }

        let threadInfo = WBBMThreadInfoModel.init()
        threadInfo.threadSequence = ""
        threadInfo.threadName = "Heaviest"
        threadInfo.stackArray = stacks
        return threadInfo
    }
    
   
    //MARK: -
    //MARK: System New Crash(bug_type:309)
    class func scanSystemNewCrashLog(content: String, uuid: String) -> WBBMLogDetailModel {
        let jsonData: Data = content.data(using: .utf8) ?? Data.init()
        let detailInfoDic: Dictionary<String,Any> = try! JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers) as? Dictionary<String,Any> ?? [:]
        
        let logDetailModel = WBBMLogDetailModel.init()
        let bundleInfo = detailInfoDic["bundleInfo"] as? Dictionary ??  [:]
        logDetailModel.identifier = bundleInfo["CFBundleIdentifier"] as? String ?? ""
        logDetailModel.hardwareModel = detailInfoDic["modelCode"] as? String ?? ""
        logDetailModel.crashTime = detailInfoDic["captureTime"] as? String ?? ""
        logDetailModel.launchTime = detailInfoDic["procLaunch"] as? String ?? ""
        let osVersion = detailInfoDic["osVersion"] as? Dictionary ??  [:]
        logDetailModel.osVersion = osVersion["train"] as? String ?? ""
        let exception = detailInfoDic["exception"] as? Dictionary ??  [:]
        logDetailModel.exceptionType = "\(exception["type"] ?? "")(\(exception["signal"] ?? ""))"
        let termination = detailInfoDic["termination"] as? Dictionary ?? [:]
        let terCode = "\(termination["code"] ?? "")"
        let terminationCode = WBBMScanLogTool.decimalToHex(decimal:String.init(format: "%@", terCode)).lowercased()
        logDetailModel.terminationReason = "namespace \(termination["namespace"] ?? "") code 0x\(terminationCode)"
        let desc = termination["description"] as? String ?? ""
        logDetailModel.terminationDescription = desc.replacingOccurrences(of: "\"", with: "“")
        let legacyInfo = detailInfoDic["legacyInfo"] as? Dictionary ?? [:]
        let triggered = legacyInfo["threadTriggered"] as? Dictionary ?? [:]
        logDetailModel.triggeredThread = "Thread \(triggered["index"] ?? "") \(triggered["queue"] ?? "")"
        
        //scan the base address&end address of all libraries
        let procName = detailInfoDic["procName"] as? String ?? ""
        logDetailModel.processName = procName
        let libraryArray = WBBMScanSystemLogTool.scanSystemLibraryAddressNewType(detailInfoDic: detailInfoDic, logDetailModel: logDetailModel, uuid: uuid)
        if libraryArray.count == 0 {
            logDetailModel.threadInfoArray = []
            return logDetailModel
        }
        
        var threadInfoArray: Array <WBBMThreadInfoModel> = Array.init()
        
        //check last exception backtrace
        if let backtrace = detailInfoDic["lastExceptionBacktrace"] as? Array<Any>{
            let backtraceInfo = WBBMThreadInfoModel.init()
            backtraceInfo.threadSequence = "Last Backtrace Stack:"
            backtraceInfo.threadName = ""
            backtraceInfo.stackArray = scanSystemNewCrashStacks(frames: backtrace, libraryArray: libraryArray)
            threadInfoArray.append(backtraceInfo)
        }
        
        //scan single thread stack
        let threads: Array<Dictionary> = detailInfoDic["threads"] as? Array <Dictionary<String, Any>> ?? []
        var threadIndex = 0
        for singleThread in threads {
            let threadInfo = WBBMThreadInfoModel.init()
            threadInfo.threadSequence = "Thread \(String(threadIndex))"
            threadInfo.threadName = "Thread Name: \((singleThread["queue"] as? String) ?? (singleThread["name"] as? String) ?? "")"
            let frames: Array<Any> = singleThread["frames"] as? Array<Any> ?? []
            threadInfo.stackArray = scanSystemNewCrashStacks(frames: frames, libraryArray: libraryArray)
            threadInfoArray.append(threadInfo)
            threadIndex += 1
        }
        
        logDetailModel.threadInfoArray = threadInfoArray
        return logDetailModel
    }
    
    class func scanSystemNewCrashStacks(frames: Array<Any>, libraryArray:Array<WBBMSystemLogNewTypeLibraryModel>) -> Array<WBBMStackModel> {
        var stacks: Array<WBBMStackModel> = Array()
        var stackIndex = 0
        for single in frames {
            let stackModel = WBBMStackModel()
            stackModel.squence = stackIndex
            
            var imageIndex = -1
            var offset = -1
            if let frame = single as? Array<Any> {
                imageIndex = frame[0] as? Int ?? -1;
                offset = frame[0] as? Int ?? -1;
            }else if let frame = single as? Dictionary<String, Any>{
                imageIndex = frame["imageIndex"] as? Int ?? -1;
                offset = frame["imageOffset"] as? Int ?? -1;
            }
            
            if imageIndex >= 0{
                let libraryModel = libraryArray[imageIndex]
                stackModel.library = libraryModel.libraryName
                stackModel.libraryStartAddress = libraryModel.libraryStartAddress
                stackModel.libraryEndAddress = libraryModel.libraryEndAddress
                
                let libraryStartInt =  Int(stackModel.libraryStartAddress) ?? 0
                if offset > libraryStartInt{
                    stackModel.address = WBBMScanLogTool.decimalToHex(decimal: String(offset))
                    stackModel.offset = String(offset - libraryStartInt)
                }else{
                    stackModel.address = WBBMScanLogTool.decimalToHex(decimal: String(libraryStartInt+offset))
                    stackModel.offset = String(offset)
                }
                
                originalResult(stackModel: stackModel)
            }

            stacks.append(stackModel)
            stackIndex += 1
        }
        return stacks
    }
    
    //MARK: -
    //MARK: Other
    class func originalResult(stackModel: WBBMStackModel) -> Void{
        let libraryStartAddress = WBBMScanLogTool.decimalToHex(decimal: stackModel.libraryStartAddress)
        
        var libraryOffset = "?"
        if stackModel.offset.count > 0 {
            libraryOffset = stackModel.offset
        }
        
        var addr = stackModel.address
        if !stackModel.address.hasPrefix("0x") && !stackModel.address.hasPrefix("0X") {
            addr = "0x\(stackModel.address)"
        }
        stackModel.analyzeResult = "\(stackModel.squence)  \(stackModel.library)\t\t\t\(addr) 0x\(libraryStartAddress) + \(libraryOffset)"
    }
}
