//
//  WBBMSymbolSearch.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/5/11.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Foundation


open class WBBMSymbolSearch {
    
    public enum SearchType {
        case finbonacci
        case binary
    }
    
    /**
     *  search symbol
     *  @param searchtype          find symbol type
     *  @param items               symbol table items
     *  @param item                the offset of stack
     *  @return                    return the symbol
     */
    open class func searchInSymbol(searchtype: SearchType = .binary, items: [String], item: Int) -> String {
        return binarySearch(items: items, item: item)
    }
    
    /**
     *  search main function offset
     *  @param items         symbol table items
     *  @return              return the main function offset
     */
    class func searchMainFuncInSymbol(items: [String]) -> Int {
        if items.count == 0 {
            return 0
        }
        
        var lastLineModel:WBBMSymbolModel = WBBMSymbolModel(items[0])
        var curIndex = 0
        for line in items{
            let symbolModel = WBBMSymbolModel(line)
//            if lastLineModel.functionName.hasPrefix("main") && lastLineModel.clasName.hasPrefix("main.m") &&
//                !symbolModel.functionName.hasPrefix("main") && !symbolModel.clasName.hasPrefix("main.m"){
//                break
//            }
            
            if lastLineModel.functionName == "wbSymbol(main)" && symbolModel.functionName != "wbSymbol(main)" {
                break
            }
            curIndex += 1
            lastLineModel = symbolModel
        }
        
        if curIndex >= items.count - 3 {
            return 0
        }
        
        let mainFuncModel = WBBMSymbolModel(items[curIndex - 3])
        let mainAddress = Int(WBBMScanLogTool.hexToDecimal(hex: mainFuncModel.start)) ?? 0
        return mainAddress + 4
    }
    
    /**
     *  binary search
     *  @param items         symbol table items
     *  @param item          the offset of stack
     *  @return              return the symbol
     */
    private class func binarySearch(items: [String], item: Int) -> String {
        
        var low = 0
        var high = items.count - 1
        while low <= high {
            let middle = (low + high) / 2   //the middle
            
            let line = items[middle]
            let symbolModel = WBBMSymbolModel(String(line))
            let startInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.start)) ?? 0
            let endInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.end)) ?? 0
            
            if item >= endInt {
                low = middle + 1
            } else if item < startInt {
                high = middle - 1
            } else {
                if symbolModel.clasName.hasSuffix("m:0") {
                    return items[middle - 1]
                }
                return line
            }
        }
        return ""
    }
}
