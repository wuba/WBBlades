//
//  WBBMSymbolModel.swift
//  WBBrightMirror
//
//  Created by zhouyingjie on 2021/5/10.
//

import Foundation


class WBBMSymbolTake {

    //MARK: 符号表拆段
    class func dismantleParagraph(_ symbolTable: String) -> [[String]]? {
        let functionTables: [String] = symbolTable.components(separatedBy: "\n")
        var integer:Int = functionTables.count/100
        let remainder:Int = functionTables.count%100

        var allTables = [[String]]()

        var index = 0

        for _ in functionTables {
            let subArr: [String] = Array(functionTables[index...index+integer])
            allTables.append(subArr)

            index += integer + 1

            if index == functionTables.count {
                break;
            }

            if index + integer + remainder > functionTables.count {
                integer = functionTables.count - index-1
            }
        }
        return allTables
    }


    //MARK: 符号表是否存在
    class func isExistSymbol(filePath: String) -> Bool {

        let fileManager = FileManager.default
        let isExist = fileManager.fileExists(atPath: filePath)
        return isExist
    }

    //MARK: 获得符号表UUID
    class func obtainSymbolUUID(_ symbolInfo: String) -> String? {

        let lines: Array<Substring> = symbolInfo.split(separator: Character.init("\n"))

        var lineIndex = 7

        let infoDic = WBBMScanSystemLogTool.checkLogHeader(lines: lines, &lineIndex, endLine: "UUID:")

        if infoDic.keys.contains("UUID") {
            return (infoDic["UUID"] as! String);
        }
        return nil
    }

    //MARK:拿到偏移地址
    class func obtainOffset(stackModel: WBBMStackModel) -> Int? {

        //去掉首尾空格 \t
        var stackAddress = stackModel.address.trimmingCharacters(in: .whitespaces)

        if stackAddress.count > 12 {
            let startI = stackAddress.index(stackAddress.startIndex, offsetBy: 9);
            stackAddress = "0x\(stackAddress[startI..<stackAddress.endIndex])"
        }
        //转十进制
        let stackAddressValue = Int(WBBMScanLogTool.hexToDecimal(hex: String(stackAddress))) ?? 0

        var  stackStartAddressValue: Int = Int(stackModel.processStartAddress) ?? 0
        if stackModel.processStartAddress.hasPrefix("0x") {
            stackStartAddressValue = Int(WBBMScanLogTool.hexToDecimal(hex: String(stackModel.processStartAddress))) ?? 0
        }

        if stackAddressValue > stackStartAddressValue {
            let offsetAddressValue = stackAddressValue - stackStartAddressValue
            return offsetAddressValue
        }
        return nil
    }

}



open class WBBMSymbolModel {
    public var start: String = ""
    public var end: String = ""
    public var functionName: String = ""
    public var clasName: String = ""

    public init(_ functionLine: String) {
        if functionLine.isEmpty {
            return
        }

        let stackAddress = functionLine.trimmingCharacters(in: .whitespaces)

        let functionLines = stackAddress.components(separatedBy:"\t")

        start = functionLines[0]
        
        if functionLines.count > 1 {
            end = functionLines[1]
        }


        if functionLines.count > 2 {
            functionName = functionLines[2]
        }

        if functionLines.count > 3 {
            clasName = functionLines[3]
        }

    }
}
