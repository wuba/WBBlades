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
    
    
    //MARK: 查找
    open class func searchInSymbol(searchtype: SearchType = .binary, items: [String], item: Int) -> String {
        if searchtype == .finbonacci {
            return finbonacciSearch(items: items, item: item)
        } else  {
            return binarySearch(items: items, item: item)
        }
    }
    
    //MARK: 查找main函数
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
    
    
    //MARK:斐波那契查找
    private static var finbonacciSequence = [Int]()
    
    //构建一个斐波那契数列
    private class func createFibonacciSequence() -> [Int] {
        var finbonacciSequence = [0,1]
        for i in 2..<40 {
            finbonacciSequence.append(finbonacciSequence[i-1] + finbonacciSequence[i-2])
        }
        print("Fibonacci数列：\(finbonacciSequence)")
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
        //        if index != 0 {
        //            return items[index]
        //        }
        return ""
    }
    
    //寻找number在Fibonacci数列中的位置
    private class func findNumberInFibonacci(number: Int) -> Int {
        var index = 0
        let finbonacciSequence = self.finbonacciSequence
        while number >= finbonacciSequence[index] {
            index += 1
        }
        return index
    }
    
    
    //查找表的元素补齐 便于Fibonacci数列进行分割
    private class func createFibonacciSearchTable(items: [String], key: Int) -> Array<String> {
        var serahItems = items
        for _ in 0..<(self.finbonacciSequence[key]-items.count) {
            serahItems.append(items.last!)
        }
        return serahItems
    }
    
    //MARK: 折半查找
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
    
    //递归查找
    //        let items = items
    //
    //        if items.count < 3 {
    //            for line in items {
    //
    //                let symbolModel = WBBMSymbolModel(String(line))
    //                let startInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.start)) ?? 0
    //                let endInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.end)) ?? 0
    //
    //                if item >= startInt && item < endInt {
    //                    return String(line)
    //                }
    //            }
    //        } else {
    //            //1.先找中间的那个
    //            let line = items[items.count/2]
    //            let symbolModel = WBBMSymbolModel(String(line))
    //
    //            let startInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.start)) ?? 0
    //            let endInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.end)) ?? 0
    //
    //            if item >= startInt && item < endInt {
    //                return String(line)
    //            } else {
    //                if item < startInt {
    //                    let newItems = Array(items[0...items.count/2])
    //                    return self.binarySearch(items: newItems, item: item)
    //                } else  {
    //                    let newItems = Array(items[items.count/2...items.count-1])
    //                    return self.binarySearch(items: newItems, item: item)
    //                }
    //            }
    //        }
    //        return ""
    //    }
    
    
    //MARK:分段查找
    //    class func reduceSymbol2(_ functionTables: [[String]]?, _ offsetAdd: Int) -> String {
    //
    //        var index = 0;
    //        for subArr: [String] in functionTables {
    //
    //            //取每个数组里面的第一个和最后一个 判断此时在不在这个区间内
    //            let firstLine = subArr.first ?? ""
    //            let lastLine = subArr.last ?? ""
    //
    //            let firstModel = WBBMSymbolModel(firstLine)
    //            let lastModel = WBBMSymbolModel(lastLine)
    //
    //            //查找区间
    //
    //            let firstValue = Int(WBBMScanLogTool.hexToDecimal(hex: firstModel.start)) ?? 0
    //            let endValue = Int(WBBMScanLogTool.hexToDecimal(hex: lastModel.end)) ?? 0
    //
    //            if offsetAdd >= firstValue && offsetAdd < endValue {
    //                //找到区间数组 在这个数组里查找
    //                for line in subArr {
    //
    //                    let symbolModel = WBBMSymbolModel(line)
    //                    let startInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.start)) ?? 0
    //                    let endInt = Int(WBBMScanLogTool.hexToDecimal(hex: symbolModel.end)) ?? 0
    //
    //                    if offsetAdd >= startInt && offsetAdd < endInt {
    //                        return line
    //                    }
    //
    //                }
    //            }
    //            index += 1
    //        }
    //        return ""
    //
    //    }
    
}