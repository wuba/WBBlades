//
//  WBAnalzeTool.swift
//  Pods-WBBladesCrashAnalyzeApp
//
//  Created by wbblades on 2021/4/22.
//

import Foundation

class WBBMShellObject{
    /**
     *  execute a task
     *  @param path         command path
     *  @param arguments    command arguments
     */
    class func launch(path:String, arguments: Array<String>) -> String? {
        let task = Process()
        task.launchPath = path
        task.arguments = arguments
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()
        
        let testData = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String.init(data: testData, encoding: .utf8)
        return output
    }
}
