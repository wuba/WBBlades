//
//  WBBMSymbolSearch.swift
//  WBBrightMirror
//
//  Created by zhouyingjie on 2021/5/11.
//

import Foundation


open class WBBMSymbolSearch {
    
    public enum SearchType {
        case finbonacci
        case binary
    }
    
    
    //MARK: search symbol
    open class func searchInSymbol(searchtype: SearchType = .binary, items: [String], item: Int) -> String {
        if searchtype == .finbonacci {
            return finbonacciSearch(items: items, item: item)
        } else  {
            return binarySearch(items: items, item: item)
        }
    }
    
    //MARK: search main function offset
    class func searchMainFuncInSymbol(items: [String]) -> Int {
        if items.count == 0 {
            return 0
        }
        
        var lastLineModel:WBBMSymbolModel = WBBMSymbolModel(items[0])
        var curIndex = 0
        for line in items{
            let symbolModel = WBBMSymbolModel(line)
            if lastLineModel.functionName.hasPrefix("main") && lastLineModel.clasName.hasPrefix("main.m") &&
                !symbolModel.functionName.hasPrefix("main") && !symbolModel.clasName.hasPrefix("main.m"){
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
    
    
    //MARK: finbonacci
    private static var finbonacciSequence = [Int]()
    
    private class func createFibonacciSequence() -> [Int] {
        var finbonacciSequence = [0,1]
        for i in 2..<40 {
            finbonacciSequence.append(finbonacciSequence[i-1] + finbonacciSequence[i-2])
        }
        print("Fibonacci Sequence：\(finbonacciSequence)")
        return finbonacciSequence
    }
    
    
    //寻找元素个数在fibonacci数列中对应区间的位置
    private class func finbonacciSearch(items: [String], item: Int) -> String {
        // var index = 0
        if self.finbonacciSequence.isEmpty {
            self.finbonacciSequence = self.createFibonacciSequence()
        }
        var key = self.findNumberInFibonacci(number: items.count)
        let serarchItems = self.createFibonacciSearchTable(items: items, key: key)
        
        //查找数据
        var low = 0
        var high = items.count - 1
        while low <= high {
            //前半部分元素的个数为F(key - 1), 那么后半部分元素的个数自然为F(key - 2)
            let mid  = low +  self.finbonacciSequence[key - 1] - 1
            //取出每行数据 计算出地址区间
            let line  = serarchItems[mid]
            let symbolModel = WBBMSymbolModel(String(line))
            let startInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.start)) ?? 0
            let endInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.end)) ?? 0
            
            if item < startInt {
                high = mid - 1
                key = key - 1 //因为查找范围的个数为F(key - 1), 所以更新key的值为key-1
            } else if (item >= endInt){
                low = mid + 1
                key = key - 2 //此刻查找范围的元素个数为F(key - 2), 更新key值
            } else {
                if mid < items.count {
                    return line
                    // index = mid
                } else {
                    return line
                    // index = items.count
                }
            }
        }
        return ""
    }
    
    //find number
    private class func findNumberInFibonacci(number: Int) -> Int {
        var index = 0
        let finbonacciSequence = self.finbonacciSequence
        while number >= finbonacciSequence[index] {
            index += 1
        }
        return index
    }
    
    
    //find the element completion
    private class func createFibonacciSearchTable(items: [String], key: Int) -> Array<String> {
        var serahItems = items
        for _ in 0..<(self.finbonacciSequence[key]-items.count) {
            serahItems.append(items.last!)
        }
        return serahItems
    }
    
    //MARK: binary search
    private class func binarySearch(items: [String], item: Int) -> String {
        
        //非递归查找
        var low = 0
        var high = items.count - 1
        while low <= high {
            let middle = (low + high) / 2   //计算本轮循环中间的位置
            
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
