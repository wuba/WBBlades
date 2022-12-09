//
//  WBScanLog.swift
//  Pods-WBBladesCrashAnalyzeApp
//
//  Created by wbblades on 2021/4/22.
//

import Foundation

class WBBMScanSystemLogTool{
    /**
     *  check the header of system crash log
     *  @param lines               crash log contents
     *  @param lastIndex           return a header last line index
     *  @param endLine             end line string
     */
    class func checkLogHeader(lines: Array<Substring>, _ lastIndex: UnsafeMutablePointer<Int>,endLine: String) -> Dictionary<String, Any>{
        var detailInfo = String.init("{")
        var lineIndex = 0;
        
        //crash log info
        for singleline in lines {
            lineIndex += 1
            if singleline.count > 0 {
                let lineArray = singleline.split(separator: Character.init(":"))
                let key = lineArray.first ?? ""
                if key == singleline {
                    continue
                }
                detailInfo.append(contentsOf: "\"\(key.trimmingCharacters(in: CharacterSet.whitespaces))\":")
            
                let start = singleline.index(singleline.startIndex, offsetBy: key.count+1)
                let value = String.init(singleline[start..<singleline.endIndex]).replacingOccurrences(of: "\"", with: "“")
                detailInfo.append("\"\(value.trimmingCharacters(in: CharacterSet.whitespaces))\",")
            }
            
            if singleline.hasPrefix(endLine) {
                detailInfo.removeLast()
                break
            }
        }
        detailInfo.append("}")
        
        let jsonData: Data = detailInfo.data(using: .utf8) ?? Data.init()
        let detailInfoDic: Dictionary<String,Any> = try! JSONSerialization.jsonObject(with: jsonData, options: .mutableContainers) as? Dictionary<String,Any> ?? [:]
        
        lastIndex.pointee = lineIndex
        return detailInfoDic
    }
    
    /**
     *  check the end line of system crash log
     *  @param line   crash log line
     */
    class func checkSystemCrashEndLine(line: String) -> Bool{
        if line.hasSuffix(WBBMSystemLogEndLine.CrashedWithArm64State.rawValue) ||
            line.hasSuffix(WBBMSystemLogEndLine.CrashedWithArm32State.rawValue) ||
            line.hasSuffix(WBBMSystemLogEndLine.BrinaryImages.rawValue) ||
            line.hasPrefix(WBBMSystemLogEndLine.WakeUpPowerStats.rawValue) {
            return true
        }
        return false
    }
    
    /**
     *  scan the address range of all libraries in the crash log content of the new system
     *  @param lines                crash log contents
     *  @param processIdentifier    the identifier of process
     *  @param processName          the name of process
     */
    class func scanSystemLibraryAddress(lines: Array<Substring>, processIdentifier: String, processName: String) -> Dictionary<String,Array<String>>{
        var libraryDic: Dictionary<String,Array<String>> = Dictionary.init()
        for singleline in lines.reversed() {
            let singleString = String(singleline)
            if WBBMScanSystemLogTool.checkSystemCrashEndLine(line: singleString) {
                break;
            }
            let singleArray = singleString.split(separator: Character.init(" "))
            if singleArray.count > 4 && singleArray[1] == "-" {
                var key = String(singleArray[3])
                if key.contains(processIdentifier) {//when the name of process is the same as the process‘s identifier in the binary images
                    key = processName
                }else if(key.contains("???")){
                    key = processName
                }
                
                let startAddress = WBBMScanLogTool.hexToDecimal(hex: String(singleArray[0]))
                let endAddress = WBBMScanLogTool.hexToDecimal(hex: String(singleArray[2]))
                libraryDic[key] = [startAddress,endAddress]
            }
        }
        return libraryDic
    }
    
    /**
     *  scan the uuid of all libraries in the crash log content
     *  @param lines                crash log contents
     *  @param processIdentifier    the identifier of process
     *  @param processName          the name of process
     */
    class func scanSystemLibraryBinaryUUID(lines: Array<Substring>, processIdentifier: String, processName: String) -> Dictionary<String,String>{
        var libraryDic: Dictionary<String,String> = Dictionary.init()
        for singleline in lines.reversed() {
            let singleString = String(singleline)
            if WBBMScanSystemLogTool.checkSystemCrashEndLine(line: singleString) {
                break;
            }
            let singleArray = singleString.split(separator: Character.init(" "))
            if singleArray.count > 6 {
                var key = String(singleArray[3])
                if key.contains(processIdentifier) {//when the name of process is the same as the process‘s identifier in the binary images
                    key = processName
                }else if(key.contains("???")){
                    key = processName
                }
                libraryDic[key] = String(singleArray[5]).replacingOccurrences(of: "<", with: "").replacingOccurrences(of: ">", with: "")
            }
        }
        return libraryDic
    }
    
    //MARK: -
    //MARK: New Crash
    /**
     *  scan the address range of all libraries in new symtem crash log content
     *  @param detailInfoDic        crash log contents
     *  @param processIdentifier    the identifier of process
     *  @param processName          the name of process
     */
    class func scanSystemLibraryAddressNewType(detailInfoDic: Dictionary<String,Any>,logDetailModel: WBBMLogDetailModel, uuid: String) -> Array<WBBMSystemLogNewTypeLibraryModel>{
        let usedImages = detailInfoDic["usedImages"] as? Array ?? [];
        
        if usedImages.count == 0 {
            return []
        }
        
        if usedImages[0] is Array<Any> {
            return scanSystemLibraryNewTypeArray(usedImages: usedImages, detailInfoDic: detailInfoDic, logDetailModel: logDetailModel, uuid: uuid);
        }
        
        if usedImages[0] is Dictionary<String, Any> {
            return scanSystemLibraryNewTypeDictionary(usedImages: usedImages,logDetailModel: logDetailModel)
        }
        
        return []
    }
    
    //array type log
    private class func scanSystemLibraryNewTypeArray(usedImages:Array<Any>,detailInfoDic: Dictionary<String,Any>,logDetailModel: WBBMLogDetailModel, uuid: String)-> Array<WBBMSystemLogNewTypeLibraryModel>{
        var libraryArray: Array<WBBMSystemLogNewTypeLibraryModel> = Array();
        
        var startAdr = 0
        for singleImages in usedImages {
            let images = singleImages as? Array ?? []
            if images.count > 1 {
                let imageUUID = images.first as? String ?? ""
                if imageUUID == uuid{
                    startAdr = images[1] as? Int ?? 0
                    break
                }
            }
        }
        
        guard startAdr > 0 else{
            return libraryArray
        }
        
        guard let legacyInfo = detailInfoDic["legacyInfo"] as? Dictionary<String,Any> else {
            return libraryArray
        }
        guard let imageExtraInfo = legacyInfo["imageExtraInfo"] as? Array<Any> else {
            return libraryArray
        }
        
        for singleExtra in imageExtraInfo {
            guard let imageExtra = singleExtra as? Dictionary<String,Any> else {
                continue
            }
            
            let imageName = imageExtra["name"] as? String ?? ""
            if imageName == logDetailModel.processName || imageName.hasPrefix("?") || imageName == "" {
                let size = imageExtra["size"] as? Int ?? 0
                let startAddress = String(startAdr)
                let endAddress = String(startAdr+size)

                let libraryModel = WBBMSystemLogNewTypeLibraryModel()
                if logDetailModel.processName == libraryModel.libraryName && startAdr == 0{
                    logDetailModel.foundedAddress = false
                }
                libraryModel.libraryName = imageName;
                libraryModel.libraryStartAddress = startAddress
                libraryModel.libraryEndAddress = endAddress
                libraryArray.append(libraryModel)
            }
        }
        
        return libraryArray
    }
    
    //dictionary type log
    private class func scanSystemLibraryNewTypeDictionary(usedImages:Array<Any>,logDetailModel: WBBMLogDetailModel)-> Array<WBBMSystemLogNewTypeLibraryModel>{
        var libraryArray: Array<WBBMSystemLogNewTypeLibraryModel> = Array();
        
        var hasMain = false
        for singleImages in usedImages {
            guard let images = singleImages as? Dictionary<String,Any> else{
                continue
            }
            
            let libraryModel = WBBMSystemLogNewTypeLibraryModel()
            libraryModel.libraryName = images["name"] as? String ?? "";
            
            let startAddress = images["base"] as? Int ?? 0
            let size = images["size"] as? Int ?? 0
            if (!hasMain && (logDetailModel.processName == libraryModel.libraryName || libraryModel.libraryName == "" || libraryModel.libraryName.hasPrefix("?"))) && startAddress == 0{
                logDetailModel.foundedAddress = false
                libraryModel.libraryName = logDetailModel.processName
            }
            
            libraryModel.libraryStartAddress = String(startAddress)
            libraryModel.libraryEndAddress = String(startAddress+size)
            if libraryModel.libraryName == logDetailModel.processName {
                hasMain = true
            }
            libraryArray.append(libraryModel)
        }
        
        return libraryArray
    }
}


class WBBMScanLogTool{
    //MARK: -
    //MARK: Hex
    class func hexToDecimal(hex: String) -> String {
        var str = hex.uppercased()
        if str.hasPrefix("0X") {
            str.removeFirst(2)
        }
        var sum = 0
        for i in str.utf8 {
            sum = sum * 16 + Int(i) - 48
            if i >= 65 {
                sum -= 7
            }
        }
        return "\(sum)"
    }
    
    class func decimalToHex(decimal: String) -> String {
        guard let decimalInt = Int(decimal) else {
            return ""
        }
        return String(format: "%llX", decimalInt)
    }
}
