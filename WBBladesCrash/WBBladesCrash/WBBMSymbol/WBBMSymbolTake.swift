//
//  WBBMSymbolModel.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/5/10.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Foundation


class WBBMSymbolTake {

    /**
     *  disassemble symbol table
     *  @param symbolTable       symbol table content
     */
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

    /**
     *  judge whether symbol table exists
     *  @param filePath       symbol table file path
     */
    class func isExistSymbol(filePath: String) -> Bool {

        let fileManager = FileManager.default
        let isExist = fileManager.fileExists(atPath: filePath)
        return isExist
    }

    /**
     *  obtain symble table's uuid
     *  @param symbolInfo       symbol table content
     */
    class func obtainSymbolUUID(_ symbolInfo: String) -> String? {

        let lines: Array<Substring> = symbolInfo.split(separator: Character.init("\n"))

        var lineIndex = 7

        let infoDic = WBBMScanSystemLogTool.checkLogHeader(lines: lines, &lineIndex, endLine: "UUID:")

        if infoDic.keys.contains("UUID") {
            return (infoDic["UUID"] as! String);
        }
        return nil
    }

    /**
     *  obtain offset
     *  @param stackModel     every stack info
     */
    class func obtainOffset(stackModel: WBBMStackModel) -> Int? {

        //remove white spacing at the beginning and end of the text
        var stackAddress = stackModel.address.trimmingCharacters(in: .whitespaces)

        if stackAddress.count > 12 {
            let startI = stackAddress.index(stackAddress.startIndex, offsetBy: 9);
            stackAddress = "0x\(stackAddress[startI..<stackAddress.endIndex])"
        }
        //decimal value
        let stackAddressValue = Int(WBBMScanLogTool.hexToDecimal(hex: String(stackAddress))) ?? 0

        var  stackStartAddressValue: Int = Int(stackModel.libraryStartAddress) ?? 0
        if stackModel.libraryStartAddress.hasPrefix("0x") {
            stackStartAddressValue = Int(WBBMScanLogTool.hexToDecimal(hex: String(stackModel.libraryStartAddress))) ?? 0
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
