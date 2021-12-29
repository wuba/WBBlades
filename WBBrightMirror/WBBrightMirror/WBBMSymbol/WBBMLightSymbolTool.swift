//
//  WBBMLightSymbolTool.swift
//  WBBrightMirror
//
//  Created by 朴惠姝 on 2021/5/14.
//

import Foundation

class WBBMLightSymbolTool {
    
    static let WBBMSymbolFileDsymType = ".dsym"
    static let WBBMSymbolFileSymbolType = ".symbol"
    static let WBBMSymbolFileAppType = ".app"
    static let WBBMSymbolFileBuglyType = ".bSymbol"
    
    static let applicationPath = String.init(format: "%@", NSSearchPathForDirectoriesInDomains(.applicationDirectory, .userDomainMask, true).first ?? "")
    
    class func checkLightSymbolPath(path: String?, processName: String, uuid: String, finishHandler:@escaping (String?)->Void) -> Void {
        guard let symbolPath = path else {
            finishHandler(nil)
            return
        }
        if symbolPath.count == 0 {
            return
        }
        
        if !FileManager.default.fileExists(atPath: symbolPath) {
            finishHandler(nil)
            return
        }
        
        if symbolPath.contains(WBBMSymbolFileSymbolType) {
            finishHandler(symbolPath)
            return
        }
        
        let outputPath = WBBMDownload.downloadPath + "/buglySymbol&" + processName + "&" + "arm64&" + uuid.replacingOccurrences(of: "-", with: "") + WBBMSymbolFileSymbolType
        
        if symbolPath.lowercased().contains(WBBMSymbolFileDsymType) {
            DispatchQueue.global().async{
//                Artillery.readDwarf(symbolPath+"/Contents/Resources/DWARF/\(processName)", outputPath: outputPath)
                DispatchQueue.main.async {
                    finishHandler(outputPath)
                }
            }
            return
        }
        
        if symbolPath.contains(WBBMSymbolFileAppType) {
            guard let fileName = Bundle.main.path(forResource: "dsymutil", ofType: "") else {
                finishHandler(nil)
                return
            }
            let exeFile = symbolPath + "/\(processName)"
            let dsymTmpPath = WBBMDownload.downloadPath + "/tmp_\(uuid).DSYM"
            DispatchQueue.global().async{
                let _ =  WBBMShellObject.launch(path: fileName, arguments: [exeFile,"-o",dsymTmpPath]) ?? ""
//                Artillery.readDwarf(dsymTmpPath+"/Contents/Resources/DWARF/\(processName)", outputPath: outputPath)
                try? FileManager.default.removeItem(atPath: dsymTmpPath)
                DispatchQueue.main.async {
                    finishHandler(outputPath)
                }
            }
            return
        }
        
        finishHandler(nil)
    }
    
    class func checkXcodeExist() -> Bool {
//        let xcodeID = "com.apple.dt.Xcode"
//        let urlArray = LSCopyApplicationURLsForBundleIdentifier(xcodeID as CFString, nil)
//        if urlArray != nil {
//            return true
//        }
        return false
    }
}
