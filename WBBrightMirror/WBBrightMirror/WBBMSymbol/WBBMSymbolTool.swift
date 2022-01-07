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
    
    //MARK:read symbol table, analyze crash log
    func readSymbol(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ isComplete: Bool, _ logModel: WBBMLogModel) -> Void) {
        let downloadDir: String = NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? ""
        let savePath = downloadDir + "/WBBrightMirror"

        var processUUID = logModel.processUUID

        if processUUID.contains("-") {
            processUUID = processUUID.replacingOccurrences(of: "-", with: "")
        }

        let filePath = symbolPath ?? savePath + "/buglySymbol&" + logModel.processName + "&" + "arm64&" + processUUID + WBBMLightSymbolTool.WBBMSymbolFileSymbolType

        if !WBBMSymbolTake.isExistSymbol(filePath: filePath){
            if !stopped {
                completionHandler(false, logModel)
            }
            return
        }

        DispatchQueue.global().async {
            let pathUrl = URL(fileURLWithPath: filePath)
            do {
                //read content
                let data = try! Data(contentsOf: pathUrl, options: .mappedRead)
                guard let content = String(data: data, encoding:
                                            String.Encoding(rawValue:
                                                                String.Encoding.utf8.rawValue))
                else {
                    return
                }
                
                //look for symbol table
                var  symbolTableArr = [String]()
                //read symbol table in cache
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

                //carsh log's UUID is different form symbol table's UUID
                if symbolUUID.uppercased() != processUUID.uppercased() {
                    let yellow = "\u{001B}[0;33m"
                    let message = "WARNING: Crash log's UUID is inconsistentand with Symbol File's UUID."
                    print(yellow + message);
//                    completionHandler(false,logModel)
//                    return
                }

                //calculate offset address
                self.dismantleLog(logModel: logModel, symbolTableArr[1]) { [weak self] (isComplete, logModel) in
//                    DispatchQueue.main.async{
                        if  self?.stopped == false{
                            completionHandler(isComplete, logModel)
                        }
//                    }
                }
            }
        }
    }

    func stopReadSymbol(logModel: WBBMLogModel) -> Void{
        self.stopped = true
    }

    //MARK: analyze
    private func dismantleLog(logModel: WBBMLogModel, _ addressTable: String, _ completionHandler: @escaping (_ isComplete: Bool,_ logModel: WBBMLogModel) -> Void) {

        self.symbolTables = addressTable.components(separatedBy: "\n")

        guard let detailModel = logModel.detailModel, !detailModel.threadInfoArray.isEmpty else {
            if !stopped {
                completionHandler(false,logModel)
            }
            return
        }

        self.allStatcks.removeAll()

        //obtain all thread stack
        var allStatckArray = [WBBMStackModel]()
        for threadInfoModel in detailModel.threadInfoArray {
            for stackModel in threadInfoModel.stackArray {
                allStatckArray.append(stackModel)
            }
        }

        // sort with offset size
        allStatckArray.sort(){
            let offsetAddValue0 = WBBMSymbolTake.obtainOffset(stackModel: $0) ?? 0
            let offsetAddValue1 = WBBMSymbolTake.obtainOffset(stackModel: $1) ?? 0
            return offsetAddValue0 < offsetAddValue1

        }
        
        var foundedStartAddress = -1
        //crash log has't process's base address,try to calculate base address in main thread
        if !logModel.detailModel.foundedAddress{
            var mainThread = logModel.detailModel.threadInfoArray[0]
            //check first line has main thread's name
            if !mainThread.threadName.hasSuffix("com.apple.main-thread"){
                //check second line has main thread's name
                mainThread = logModel.detailModel.threadInfoArray[1]
            }
            if mainThread.threadName.hasSuffix("com.apple.main-thread") {
                let stackCount = mainThread.stackArray.count
                //obtain main thread's penultimate line, is most likely the main function
                let mainFunc = mainThread.stackArray[stackCount - 2];
                //obtain main function's offset in symbol table
                let mainFuncOffset = WBBMSymbolSearch.searchMainFuncInSymbol(items: self.symbolTables)
                let mainFuncDecimal = Int(WBBMScanLogTool.hexToDecimal(hex: mainFunc.address)) ?? 0
                //calculate base address = main function address - main function offset
                foundedStartAddress = mainFuncDecimal - mainFuncOffset//founded!
            }else{
                if !stopped {
                    completionHandler(false,logModel)
                }
                return
            }
        }
        
        //not found base address, then can't analyze crash log
        if !stopped && !logModel.detailModel.foundedAddress && foundedStartAddress <= 0 {
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
           
            //obtain offset
            guard let offset = WBBMSymbolTake.obtainOffset(stackModel: stackModel) else {
                continue
            }

            //judge cache
            if (self.allStatcks.keys.contains(String(offset))) {
                stackModel.analyzeResult = self.allStatcks[String(offset)] ?? ""
                continue
            }

            //look for symbol
            let resultLine = WBBMSymbolSearch.searchInSymbol(items: self.symbolTables, item: offset)

            if resultLine.isEmpty {//not found
                continue
            }
            let symbolModel = WBBMSymbolModel(resultLine)

            var stackAddress = stackModel.address
            let addresArr = stackModel.address.components(separatedBy: "\t")
            if addresArr.count == 2 {
                stackAddress = addresArr[1]
            }
            
            let analyzes = [String(stackModel.squence),"",stackModel.process,"\t\t\t ",stackAddress,"",symbolModel.functionName,"",symbolModel.clasName]
            stackModel.analyzeResult =  analyzes.joined(separator: " ")

            //save result
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
            return nil
        }

        let pathUrl = URL(fileURLWithPath: filePath)

        do {
            //read content
            let data = try! Data(contentsOf: pathUrl, options: .mappedRead)

            guard let content = String(data: data, encoding: String.Encoding(rawValue: String.Encoding.utf8.rawValue)) else {
                return nil
            }

            //segmentation
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
