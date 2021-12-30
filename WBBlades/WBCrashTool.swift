//
//  Dummy.swift
//  WBBlades
//
//  Created by 朴惠姝 on 2021/12/28.
//  Copyright © 2021 邓竹立. All rights reserved.
//

import Foundation
import WBBrightMirror

@objc public class WBCrashTool: NSObject{
    static let deskTopConfigPath = String.init(format: "%@%@", NSSearchPathForDirectoriesInDomains(.desktopDirectory, .userDomainMask, true).first ?? "","/blade-config.json")
    
    static var logModel: WBBMLogModel?
    
    @objc class func scanCrash(logPath: NSString?) -> Bool{
        guard let path = logPath, path.length > 0 else{
            crashErrorPrint(string: "No such file or directory.")
            return false;
        }
        
        guard let fileString = try? String.init(contentsOfFile: path as String) else{
            crashErrorPrint(string: "Unable to read file.")
            return false
        }
        
        logModel = WBBrightMirrorManager.scanLog(logString: fileString)
        if logModel == nil {
            crashErrorPrint(string: "Analyze log failed, try again.")
            return false
        }
        
        crashNormalPrint(string: "Crash APP's UUID: " + (logModel?.processUUID ?? ""))
        
        return true
    }
    
    @objc class func startSymbolicate(symbolPath: NSString?){
        guard let path = symbolPath as String?, path.count > 0 else{
            print("No such file or directory.")
            return;
        }
        
        WBBrightMirrorManager.startAnalyze(logModel: logModel!, symbolPath: path) { succeed, symbolReady, outputPath in
            if symbolReady{
                crashNormalPrint(string: "Symbol File Ready.")
                crashNormalPrint(string: "Waiting for symbolicate finish...")
            }else if succeed{
                crashNormalPrint(string: "Symbolicate Succeed! Result is writted in ")
                if outputPath != nil {
                    print(outputPath!)
                }
                NSWorkspace.shared.selectFile(outputPath, inFileViewerRootedAtPath: "")
                exit(0)
            }else{
                crashErrorPrint(string: "Symbolicate Failed!")
                exit(0)
            }
        }
    }
    
    class func crashErrorPrint(string: String){
        let redColor = "\u{001B}[0;31m"
        print(redColor + string);
    }
    
    class func crashNormalPrint(string: String){
        let whiteColor = "\u{001B}[0;37m"
        print(whiteColor + string);
    }
}
