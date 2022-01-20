//
//  WBBMLightSymbolTool.swift
//  WBBladesCrash
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
    
    /**
     *  check the symbol file whether is a light symbol
     *  @param path                original symbol path
     *  @param processName         process name
     *  @param finishHandler       return a light symbol file path
     */
    class func checkLightSymbolPath(path: String?, processName: String, uuid: String, finishHandler:@escaping (String?)->Void) -> Void {
        guard let symbolPath = path?.replacingOccurrences(of: "\\", with: ""), symbolPath.count > 0 else {
            finishHandler(nil)
            return
        }
        
        //whether the file exists
        if !FileManager.default.fileExists(atPath: symbolPath) {
            finishHandler(nil)
            return
        }
        
        //whether the file is a light symbol file
        if symbolPath.contains(WBBMSymbolFileSymbolType) {
            finishHandler(symbolPath)
            return
        }
        
        //check result path exist
        if !FileManager.default.fileExists(atPath: WBBMOutputFile.downloadPath) {
            try? FileManager.default.createDirectory(atPath: (WBBMOutputFile.downloadPath), withIntermediateDirectories: true, attributes: nil)
        }
        
        let outputPath = WBBMOutputFile.downloadPath + "/buglySymbol&" + processName + "&" + "arm64&" + uuid.replacingOccurrences(of: "-", with: "") + WBBMSymbolFileSymbolType
        
        //.dsym file need strip a light symbol file
        if symbolPath.lowercased().contains(WBBMSymbolFileDsymType) {
            DispatchQueue.global().async{
                //strip a light symbol file
                Artillery.readDwarf(symbolPath+"/Contents/Resources/DWARF/\(processName)", outputPath: outputPath)
                DispatchQueue.main.async {
                    finishHandler(outputPath)
                }
            }
            return
        }
        
        //.app file need strip a light symbol file
        if symbolPath.contains(WBBMSymbolFileAppType) {
            guard let fileName = Bundle.main.path(forResource: "dsymutil", ofType: "") else {
                finishHandler(nil)
                return
            }
            let exeFile = symbolPath + "/\(processName)"
            let dsymTmpPath = WBBMOutputFile.downloadPath + "/tmp_\(uuid).DSYM"
            DispatchQueue.global().async{
                //at first, strip a dsym symbol file
                let _ =  WBBMShellObject.launch(path: fileName, arguments: [exeFile,"-o",dsymTmpPath]) ?? ""
                //strip a light symbol file
                Artillery.readDwarf(dsymTmpPath+"/Contents/Resources/DWARF/\(processName)", outputPath: outputPath)
                try? FileManager.default.removeItem(atPath: dsymTmpPath)
                DispatchQueue.main.async {
                    finishHandler(outputPath)
                }
            }
            return
        }
        
        finishHandler(nil)
    }
}
