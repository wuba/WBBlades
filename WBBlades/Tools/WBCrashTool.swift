//
//  Dummy.swift
//  WBBlades
//
//  Created by wbblades on 2021/12/28.
//  Copyright © 2021 58.com. All rights reserved.
//

import Foundation
import WBBladesCrash

@objc public class WBCrashTool: NSObject{
    static var logModel: WBBMLogModel?
    
    /**
     *  scan the log type
     *  @param  logPath          the original log path
     */
    @objc class func scanCrash(logPath: NSString?) -> Bool{
        guard let path = logPath, path.length > 0 else{
            crashErrorPrint(string: "No such file or directory.")
            return false;
        }
        
        guard let fileString = try? String.init(contentsOfFile: path as String) else{
            crashErrorPrint(string: "Unable to read file.")
            return false
        }
        
        logModel = WBBladesCrashManager.scanLog(logString: fileString)
        if logModel == nil {
            crashErrorPrint(string: "Analyze log failed, try again.")
            return false
        }
        
        crashNormalPrint(string: "Crash APP's UUID: " + (logModel?.processUUID ?? ""))
        
        return true
    }
    
    /**
     *  analyze the crash log
     *  @param  symbolPath          the symbol table file path
     */
    @objc class func startSymbolicate(symbolPath: NSString?){
        guard let path = symbolPath as String?, path.count > 0 else{
            print("No such file or directory.")
            return;
        }
        
        WBBladesCrashManager.startAnalyze(logModel: logModel!, symbolPath: path) { succeed, symbolReady, outputPath in
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
    
    /**
     *  console print error message
     *  @param  string         message
     */
    class func crashErrorPrint(string: String){
        let redColor = "\u{001B}[0;31m"
        print(redColor + string);
    }
    
    /**
     *  console print normal message
     *  @param  string         message
     */
    class func crashNormalPrint(string: String){
        let whiteColor = "\u{001B}[0;37m"
        print(whiteColor + string);
    }
}
