//
//  WBBMSymbolTool.swift
//  Pods
//
//  Created by wbblades on 2021/4/25.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

open class WBBMSymbolTool: NSObject {

    private var allStatcks = [String:String]()
    private var symbolTables = [String]()
    private var stopped = false
    private var symbolTableDict = [String:[String]]()

    /**
     *  start analyzing
     *  @param logModel         analyzed log model
     *  @param symbolPath       the absolute path of symbol table
     *  @param completionHandler     analyzing finish handler
     */
    open class func startAnalyze(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ isComplete: Bool,_ fromDsym: String?, _ logModel: WBBMLogModel) -> Void) {
        let symbolTool = WBBMSymbolTool()
        logModel.analyzeTool = symbolTool
        symbolTool.readSymbol(logModel: logModel, symbolPath: symbolPath) { complete, resultLogModel in
            completionHandler(complete,nil,resultLogModel)
        }
    }
    
    /**
     *  stop analyzing
     *  @param logModel         analyzed log model
     */
    class func stopAnalyze(logModel: WBBMLogModel) {
        let symbolTool = logModel.analyzeTool
        symbolTool?.stopReadSymbol(logModel: logModel)
        symbolTool?.allStatcks.removeAll()
        symbolTool?.symbolTables.removeAll()
    }
    
    /**
     *  read symbol table, analyze crash log
     *  @param logModel         analyzed log model
     *  @param symbolPath       the absolute path of symbol table
     *  @param completionHandler     analyzing finish handler
     */
    func readSymbol(logModel: WBBMLogModel, symbolPath: String?, _ completionHandler: @escaping (_ isComplete: Bool, _ logModel: WBBMLogModel) -> Void) {
        let downloadDir: String = NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? ""
        let savePath = downloadDir + "/WBBladesCrash"

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
                
                let symbolTableArr = content.components(separatedBy: "Symbol table:")

                guard let symbolUUID = WBBMSymbolTake.obtainSymbolUUID(symbolTableArr[0]) else {
                    completionHandler(false,logModel)
                    return
                }

                //When UUID of crash log is different from that of symbol table.
                if symbolUUID.uppercased() != processUUID.uppercased() {
                    let yellow = "\u{001B}[0;33m"
                    let message = "WARNING: UUID of crash log is inconsistent with that of symbol table."
                    print(yellow + message);
                }

                //calculate offset
                self.dismantleLog(logModel: logModel, symbolTableArr[1]) { [weak self] (isComplete, logModel) in
                    if  self?.stopped == false{
                        completionHandler(isComplete, logModel)
                    }
                }
            }
        }
    }

    /**
     *  stop reading symbol
     *  @param logModel         analyzed log model
     */
    func stopReadSymbol(logModel: WBBMLogModel) -> Void{
        self.stopped = true
    }

    /**
     *  analyze the log
     *  @param logModel                 analyzed log model
     *  @param addressTable             function offset address
     *  @param completionHandler        analyzing finish handler
     */
    private func dismantleLog(logModel: WBBMLogModel, _ addressTable: String, _ completionHandler: @escaping (_ isComplete: Bool,_ logModel: WBBMLogModel) -> Void) {

        self.symbolTables = addressTable.components(separatedBy: "\n")
        self.symbolTables.remove(at: self.symbolTables.count - 1)

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

        //sort with offset size
        allStatckArray.sort(){
            let offsetAddValue0 = WBBMSymbolTake.obtainOffset(stackModel: $0) ?? 0
            let offsetAddValue1 = WBBMSymbolTake.obtainOffset(stackModel: $1) ?? 0
            return offsetAddValue0 < offsetAddValue1

        }
        
        var foundedStartAddress = -1
        //if crash log doesn’t include the base address of the process, it will try to calculate base address with main thread.
        if !logModel.detailModel.foundedAddress{
            var mainThread = logModel.detailModel.threadInfoArray[0]
            //Check whether the first line has the name of the main thread
            if !mainThread.threadName.hasSuffix("com.apple.main-thread"){
                //Check whether the second line has the name of the main thread
                mainThread = logModel.detailModel.threadInfoArray[1]
            }
            if mainThread.threadName.hasSuffix("com.apple.main-thread") {
                let stackCount = mainThread.stackArray.count
                //obtain penultimate line of the main thread, it is the main function with a high probability.
                let mainFunc = mainThread.stackArray[stackCount - 2];
                //obtain the offset of main function in symbol table
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
        
        //If the base address is not found, then it cannot be analysed
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
            if stackModel.library != logModel.processName {
                continue
            }
            
            if foundedStartAddress > 0 {
                stackModel.libraryStartAddress = "\(foundedStartAddress)"
            }
           
            //obtain offset
            guard let offset = WBBMSymbolTake.obtainOffset(stackModel: stackModel) else {
                continue
            }

            //judge whether the cache exists
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
            
            let analyzes = [String(stackModel.squence),"",stackModel.library,"\t\t\t ",stackAddress,"",symbolModel.functionName,"",symbolModel.clasName]
            stackModel.analyzeResult =  analyzes.joined(separator: " ")

            //save result
            allStatcks[String(offset)] = stackModel.analyzeResult
        }
        
        self.allStatcks.removeAll()
        self.symbolTables.removeAll()
        
        //finished!
        if !self.stopped {
            completionHandler(true,logModel)
        }
    }

    /**
     *  find the offset address by the function name
     *  @param functionName     the function name
     *  @param logModel         analyzed log model
     *  @param symbolPath       the absolute path of symbol table
     */
    class func searchFunctionInfo(functionName: String, logModel: WBBMLogModel, symbolPath: String?) -> WBBMSymbolModel? {

        let downloadDir: String = NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? ""
        let savePath = downloadDir + "/WBBladesCrash"

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

    /**
     *  alert tool
     *  @param message   alert message
     */
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
