//
//  WBBMSymbolTool.swift
//  Pods
//
//  Created by zhouyingjie on 2021/4/25.
//

import Cocoa

open class WBBMSymbolTool: NSObject {

    private var allStatcks = [String:String]()
    private var symbolTables = [String]()
    private var stopped = false
    private var symbolTableDict = [String:[String]]()

    open class func startAnalyze(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ isComplete: Bool,_ fromDsym: String?, _ logModel: WBBMLogModel) -> Void) {
        let symbolTool = WBBMSymbolTool()
        logModel.analyzeTool = symbolTool
        
        let dsymPath = WBBMDownload.downloadPath + "/\(logModel.processName)_\(logModel.processUUID+WBBMLightSymbolTool.WBBMSymbolFileDsymType)"
        //用DSYM文件直接解，暂时跳过
        if logModel.originalLogPath != nil && logModel.originalLogPath.absoluteString.count > 0 && WBBMLightSymbolTool.checkXcodeExist() && FileManager.default.fileExists(atPath: dsymPath)  {
            DispatchQueue.global().async{
                let resourcePath = Bundle.main.resourcePath ?? ""
                let symbolicate = WBBMDownload.downloadPath+"/symbolicatecrash"
                
                if !FileManager.default.fileExists(atPath: symbolicate) {
                    let appSymbolicatePath = resourcePath + "/symbolicatecrash"
                    guard FileManager.default.fileExists(atPath: appSymbolicatePath) else{
                        DispatchQueue.main.async {
                            completionHandler(false,nil,logModel)
                        }
                        return
                    }
                    
                    try? FileManager.default.copyItem(atPath: appSymbolicatePath, toPath: symbolicate)
                }
                
                guard FileManager.default.fileExists(atPath: symbolicate) else {
                    DispatchQueue.main.async {
                        completionHandler(false,nil,logModel)
                    }
                    return
                }
                
                let outputPath = WBBMOutputFile.resultPath(fileName: "\(logModel.processName)_\(logModel.detailModel.crashTime)")
                
                let tmpFilePath = WBBMDownload.downloadPath+"/tmp.ips"
                let originalContent = try? String.init(contentsOf: logModel.originalLogPath, encoding: .utf8)
                
                let lineArray = originalContent?.split(separator: "\n") ?? []
                var newContent = ""
                for line in lineArray{
                    var newLine = String(line)
                    if line.contains("???") {
                        newLine = newLine.replacingOccurrences(of: "???", with: logModel.processName)
                    }
                    newContent.append("\(newLine)\n")
                }
                try? newContent.write(toFile: tmpFilePath, atomically: true, encoding: .utf8)

                let shContent = String.init(format: "cd ~/Downloads/WBBrightMirror/\nexport DEVELOPER_DIR=\"/Applications/XCode.app/Contents/Developer\"\n./symbolicatecrash %@ %@ > crash.txt", tmpFilePath,dsymPath)

                let shFilePath = WBBMDownload.downloadPath+"/tmpsh_\(logModel.processName).sh"
                try? shContent.write(toFile: shFilePath, atomically: true, encoding: .utf8)
                _ = WBBMShellObject.launch(path: "/bin/sh", arguments: [shFilePath])
                
                let crashResultPath = WBBMDownload.downloadPath + "/crash.txt"
                try? FileManager.default.copyItem(atPath: crashResultPath, toPath: outputPath)
                
                try? FileManager.default.removeItem(atPath: crashResultPath)
                try? FileManager.default.removeItem(atPath: shFilePath)
                try? FileManager.default.removeItem(atPath: tmpFilePath)
                
                DispatchQueue.main.async {
                    completionHandler(true,outputPath,logModel)
                }
            }
            return
        }
        symbolTool.readSymbol(logModel: logModel, symbolPath: symbolPath) { complete, resultLogModel in
            completionHandler(complete,nil,resultLogModel)
        }
    }
    
    class func stopAnalyze(logModel: WBBMLogModel) {
        let symbolTool = logModel.analyzeTool
        symbolTool?.stopReadSymbol(logModel: logModel)
        symbolTool?.allStatcks.removeAll()
        symbolTool?.symbolTables.removeAll()
    }
    
    //MARK:读取符号表 拿到结果
    func readSymbol(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ isComplete: Bool, _ logModel: WBBMLogModel) -> Void) {
        let downloadDir: String = NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? ""
        let savePath = downloadDir + "/WBBrightMirror"

        var processUUID = logModel.processUUID

        if processUUID.contains("-") {
            processUUID = processUUID.replacingOccurrences(of: "-", with: "")
        }

        let filePath = symbolPath ?? savePath + "/buglySymbol&" + logModel.processName + "&" + "arm64&" + processUUID + WBBMLightSymbolTool.WBBMSymbolFileSymbolType

        if !WBBMSymbolTake.isExistSymbol(filePath: filePath){
            //            self.showAlert("符号表不存在，请下载符号表")
            if !stopped {
                completionHandler(false, logModel)
            }
            return
        }

        DispatchQueue.global().async {

            let pathUrl = URL(fileURLWithPath: filePath)

            do {
                //读取内容
                let data = try! Data(contentsOf: pathUrl, options: .mappedRead)
                guard let content = String(data: data, encoding:
                                            String.Encoding(rawValue:
                                                                String.Encoding.utf8.rawValue))
                else {
                    return
                }
                
                //查找符号表UUID
                var  symbolTableArr = [String]()

                //如果缓存里有符号表 直接取
                if let cacheSymbolTaleDict = UserDefaults.standard.value(forKey: "kWB_Symbol_Table") as? [String:[String]] {
                    if let cacheSymbolTables = cacheSymbolTaleDict[logModel.processUUID],
                       !cacheSymbolTables.isEmpty {
                        symbolTableArr = cacheSymbolTables
                    } else {
                        symbolTableArr = content.components(separatedBy: "Symbol table:")
                        self.symbolTableDict[logModel.processUUID] = symbolTableArr
                        UserDefaults.standard.setValue(self.symbolTableDict, forKey: "kWB_Symbol_Table")
                        UserDefaults.standard .synchronize();
                    }
                } else {
                    symbolTableArr = content.components(separatedBy: "Symbol table:")
                    self.symbolTableDict[logModel.processUUID] = symbolTableArr
                    UserDefaults.standard.setValue(self.symbolTableDict, forKey: "kWB_Symbol_Table")
                    UserDefaults.standard .synchronize();
                }


                guard let symbolUUID = WBBMSymbolTake.obtainSymbolUUID(symbolTableArr[0]) else {
                    completionHandler(false,logModel)
                    return
                }

                //如果 carsh 文件的 UUID 与 symbol UUID 不一致
                if symbolUUID.uppercased() != processUUID.uppercased() {
                    completionHandler(false,logModel)
                    return
                }

                //计算偏移地址
                self.dismantleLog(logModel: logModel, symbolTableArr[1]) { [weak self] (isComplete, logModel) in
                    DispatchQueue.main.async{
                        if  self?.stopped == false{
                            completionHandler(isComplete, logModel)
                        }
                    }
                }
            }
        }
    }

    func stopReadSymbol(logModel: WBBMLogModel) -> Void{
        self.stopped = true
    }

    //MARK: 解析logModel
    private func dismantleLog(logModel: WBBMLogModel, _ addressTable: String, _ completionHandler: @escaping (_ isComplete: Bool,_ logModel: WBBMLogModel) -> Void) {

        self.symbolTables = addressTable.components(separatedBy: "\n")

        guard let detailModel = logModel.detailModel, !detailModel.threadInfoArray.isEmpty else {
            if !stopped {
                completionHandler(false,logModel)
            }
            return
        }

        self.allStatcks.removeAll()

        //全部排序
        var allStatckArray = [WBBMStackModel]()
        for threadInfoModel in detailModel.threadInfoArray {
            for stackModel in threadInfoModel.stackArray {
                allStatckArray.append(stackModel)
            }
        }

        // 从小到大排序
        allStatckArray.sort(){
            let offsetAddValue0 = WBBMSymbolTake.obtainOffset(stackModel: $0) ?? 0
            let offsetAddValue1 = WBBMSymbolTake.obtainOffset(stackModel: $1) ?? 0
            return offsetAddValue0 < offsetAddValue1

        }
        
        var foundedStartAddress = -1
        //修正，若日志中取不到进程的起始地址，尝试通过main函数来计算进程的起始地址
        if !logModel.detailModel.foundedAddress{
            var mainThread = logModel.detailModel.threadInfoArray[0]
            if !mainThread.threadName.hasSuffix("com.apple.main-thread") {//如果第一个不是，查第二个是否为主线程(主要是有Lastbacktrace的时候)
                mainThread = logModel.detailModel.threadInfoArray[1]
            }
            if mainThread.threadName.hasSuffix("com.apple.main-thread") {
                let stackCount = mainThread.stackArray.count
                let mainFunc = mainThread.stackArray[stackCount - 2];
                let mainFuncOffset = WBBMSymbolSearch.searchMainFuncInSymbol(items: self.symbolTables)
                let mainFuncDecimal = Int(WBBMScanLogTool.hexToDecimal(hex: mainFunc.address)) ?? 0
                foundedStartAddress = mainFuncDecimal - mainFuncOffset
            }else{
                if !stopped {
                    completionHandler(false,logModel)
                }
                return
            }
        }
        
        if !stopped && !logModel.detailModel.foundedAddress && foundedStartAddress <= 0 {//日志中取不到进程的起始地址,但是通过main函数也依然找不到起始地址
            completionHandler(false,logModel)
            return
        }

        var index = 0

        for stackModel in allStatckArray {
            index += 1
            if self.stopped {
                break
            }
            if stackModel.process != logModel.processName {
                continue
            }
            
            if foundedStartAddress > 0 {
                stackModel.processStartAddress = "\(foundedStartAddress)"
            }
           
            //拿到偏移地址后 去符号表里查找
            guard let offset = WBBMSymbolTake.obtainOffset(stackModel: stackModel) else {
                continue
            }

            //如果历史里有
            if (self.allStatcks.keys.contains(String(offset))) {
                stackModel.analyzeResult = self.allStatcks[String(offset)] ?? ""
                continue
            }

            //查找错误
            let resultLine = WBBMSymbolSearch.searchInSymbol(items: self.symbolTables, item: offset)

            if resultLine.isEmpty {
                continue
            }
            let symbolModel = WBBMSymbolModel(resultLine)

            var stackAddress = stackModel.address
            let addresArr = stackModel.address.components(separatedBy: "\t")
            if addresArr.count == 2 {
                stackAddress = addresArr[1]
            }
            
            var functionName = symbolModel.functionName;
            if functionName.hasPrefix("_Tt") {
//                functionName = WBBMScanLogTool.getDemangleName(mangleName: functionName)
            }
            let analyzes = [String(stackModel.squence),"",stackModel.process,"\t\t\t ",stackAddress,"",symbolModel.functionName,"",symbolModel.clasName]
            stackModel.analyzeResult =  analyzes.joined(separator: " ")

            //存贮
            allStatcks[String(offset)] = stackModel.analyzeResult
        }
        
        self.allStatcks.removeAll()
        self.symbolTables.removeAll()
        
        //全部查找完成
        if !self.stopped {
            completionHandler(true,logModel)
        }
    }


    //MARK: 根据函数名查找偏移地址
    class func searchFunctionInfo(functionName: String, logModel: WBBMLogModel, symbolPath: String?) -> WBBMSymbolModel? {

        let downloadDir: String = NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? ""
        let savePath = downloadDir + "/WBBrightMirror"

        var processUUID = logModel.processUUID

        if processUUID.contains("-") {
            processUUID = processUUID.replacingOccurrences(of: "-", with: "")
        }

        let filePath = symbolPath ?? savePath + "/buglySymbol&" + logModel.processName + "&" + "arm64&" + processUUID + WBBMLightSymbolTool.WBBMSymbolFileSymbolType

        if !WBBMSymbolTake.isExistSymbol(filePath: filePath){
            //            self.showAlert("符号表不存在，请下载符号表")
            return nil
        }

        let pathUrl = URL(fileURLWithPath: filePath)

        do {
            //读取内容
            //当前时间的时间戳
            let data = try! Data(contentsOf: pathUrl, options: .mappedRead)

            guard let content = String(data: data, encoding: String.Encoding(rawValue: String.Encoding.utf8.rawValue)) else {
                return nil
            }

            //分割
            let symbolTableArr = content.components(separatedBy: "Symbol table:")
            let addressTable = symbolTableArr[1];


            let symbolTables = addressTable.components(separatedBy: "\n")

            var resultLine = ""
            for function in symbolTables {
                if function.contains(functionName) {
                    resultLine = function
                    break
                }
            }

            return  WBBMSymbolModel(resultLine)
        }
    }


    public func showAlert(_ message: String) {
        DispatchQueue.main.async{
            let alert:NSAlert = NSAlert()
            alert.messageText = message
            alert.addButton(withTitle: "ok")
            alert.alertStyle = .critical
            alert.runModal()
        }
    }
}

private struct WBBMLogModelSymbolStruct{
    static var symbolTool: WBBMSymbolTool?
}

extension WBBMLogModel{
    var analyzeTool: WBBMSymbolTool? {
        get{
            return objc_getAssociatedObject(self, &WBBMLogModelSymbolStruct.symbolTool) as? WBBMSymbolTool
        }
        set{
            objc_setAssociatedObject(self, &WBBMLogModelSymbolStruct.symbolTool, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        }
    }
}
