//
//  WBBMOutputFile.swift
//  WBBrightMirror
//
//  Created by 朴惠姝 on 2021/5/10.
//

import Foundation

class WBBMOutputFile {
    static let downloadPath = String.init(format: "%@%@", NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? "","/WBBrightMirror")
    static let outputDir = String.init(format: "%@%@", NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? "","/WBBrightMirror/output")
    
    class func outputResultFile(logResultModel: WBBMLogModel, _ completionHandler: @escaping (_ succeed: Bool, _ outputPath: String?) -> Void){
        
        guard let detailModel = logResultModel.detailModel else{
            completionHandler(false,nil)
            return
        }
        
        var resultString = String()
        resultString.append("\(detailModel.headerLogString)\n\n")
        
        for threadModel in detailModel.threadInfoArray  {
            var threadSqu = ""
            if threadModel.threadSequence.count > 0 {
                threadSqu = "\(threadModel.threadSequence) : "
            }
            resultString.append("\(threadSqu)\(threadModel.threadName)\n")
            if "Thread \(detailModel.triggeredThread)" == threadModel.threadSequence {
                resultString.append("\(threadModel.threadSequence) Crashed:\n")
            }
            for stachModel in threadModel.stackArray {
                resultString.append("\(stachModel.analyzeResult)\n")
            }
            resultString.append("\n")
        }
        
        let outputPath = saveResult(resultString: resultString, processName: logResultModel.processName, crashTime: detailModel.crashTime)
        if outputPath == nil {
            completionHandler(false,nil)
        }else{
            completionHandler(true,outputPath)
        }
    }

    class func saveResult(resultString: String?, processName: String, crashTime: String?) -> String?{
        let outputPath = resultPath(fileName: "\(processName)_\(crashTime ?? "")")
        
        try? resultString?.write(toFile: outputPath, atomically: true, encoding: .utf8)
        if !FileManager.default.fileExists(atPath: outputPath) {
            return nil
        }
        
        return outputPath
    }
    
    class func resultPath(fileName: String) -> String{
        let outputPath = "\(outputDir)/\(fileName).txt"
        try? FileManager.default.createDirectory(atPath: (outputDir), withIntermediateDirectories: true, attributes: nil)
        return outputPath
    }
    
    class func cleanAllCache() -> Void {
        if FileManager.default.fileExists(atPath: downloadPath) {
            try? FileManager.default.removeItem(atPath: downloadPath)
            try? FileManager.default.createDirectory(atPath: (downloadPath), withIntermediateDirectories: true, attributes: nil)
        }
    }
}
