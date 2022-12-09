//
//  DiagnoseDataManager.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/30.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class DiagnoseDataManager: NSObject {
    
    var sizeItemList : [SizeProfileModel]?
    var dataResult : ASMainBundle?
    var diagnoseResult = [DiagnoseModel]()
    var totalOptimSize : Double = 0
    
    lazy var totalSize: UInt! = {
        return self.dataResult?.all.totalSize
    }()
    /**
     对APP诊断
     */
    func diagnoseApp(withApp appPath: String, andProgressBlock progressBlock:@escaping((_ hint:String) -> Void), andFinishBlock completeBlock:@escaping(() -> Void) ) {
        DispatchQueue.global().async {
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep1"))
            let binaryPath = self.mainBinaryFilePath(appPath: appPath)
            MachOCheck.preHandleMainBinary(binaryPath)
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep2"))
            self.dataResult = ASFileManager.mainBundle(withAppPath: appPath)
            self.diagnoseResult.removeAll()
            // 获取诊断结果
            self.sizeItemList = self.computeAppSizeProfile()
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep3"))
            // 无用类检测
            self.obtainUnusedClasses(appPath: appPath)
//            self.totalOptimSize = self.totalOptimSize + self.obtainUnusedClasses(appPath: appPath)
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep4"))
            // 获取strip结果
            self.totalOptimSize = self.totalOptimSize + self.obtainStripResult(appPath: appPath)
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep5"))
            // 获取段迁移诊断结果
            self.totalOptimSize = self.totalOptimSize + self.obtainSegmentMigrateResult(appPath: appPath)
            // 获取LTO诊断结果
            self.totalOptimSize = self.totalOptimSize + self.obtainLTOResult()
            progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep6"))
            ASFileManager.unzipCar(at: self.dataResult) {
                DispatchQueue.global().async {
                    // Asset Catalog图片检测
                    progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep7"))
                    self.totalOptimSize = self.totalOptimSize + self.obtainPngOutofAssets()
                    progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep8"))
                    // 获取无用资源
                    self.totalOptimSize = self.totalOptimSize + self.obtainUnusedResources(bundleData: self.dataResult)
                    //重复资源检测结果
                    progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep9"))
                    self.totalOptimSize = self.totalOptimSize + self.obtainDuplicateRes()
                    progressBlock(ASTextDictionary.valueForKey(key: "diagnoseStep10"))
                    // 回调
                    completeBlock()
                }
            }
        }
    }
    /**
     计算APP各模块大小
     */
    func computeAppSizeProfile() -> [SizeProfileModel] {
        var sizeList : [SizeProfileModel] = []
        let allInfo = self.dataResult?.all
        // 可执行文件大小
        let exeFileSize = allInfo?.machOSize ?? 0
//        let exeFileSize = (mainAppInfo?.machOSize)! + (allInfo?.frameworkSize)! + (allInfo?.pluginSize)!
        var model = SizeProfileModel.init(itype: ItemType.EXEBinary, itemSize: exeFileSize)
        sizeList.append(model)
        // Assets图片
        let assetsSize = allInfo?.carSize ?? 0
        model = SizeProfileModel.init(itype: ItemType.ImageInAssets, itemSize: assetsSize)
        sizeList.append(model)
        // Assets外图片
        let pngSize = allInfo?.pngSize ?? 0
        model = SizeProfileModel.init(itype: ItemType.ImageOutofAssets, itemSize: pngSize )
        sizeList.append(model)
        // 其它资源
        let notOtherSize:UInt = exeFileSize + assetsSize + pngSize
        let otherSize = self.totalSize! - notOtherSize
        model = SizeProfileModel.init(itype: ItemType.OtherRes, itemSize: otherSize)
        sizeList.append(model)
        return sizeList
    }
    
    /**
     获取无用的资源
     */
    func obtainUnusedResources(bundleData : ASMainBundle?) -> Double {
        guard let bundleData = bundleData else {
            return 0.0
        }
        let unusedRes: [ASBaseFile] = ASFileManager.checkUnusedAssetsOfBundle(byDefault: bundleData)
        if unusedRes.count == 0 {
            return 0.0
        }
        var modelList = [DiagnoseModel]()
        var resSize: Double = 0.0
        var index = 0
        let pngDic: NSMutableDictionary = NSMutableDictionary()
        for pngImg in unusedRes {
            let imgSize = (Double)(pngImg.inputSize) / 1000.0
            resSize = resSize + imgSize
            let imgName: String = pngImg.bundleName == "main" ? pngImg.fileName : String(format: "%@/%@", pngImg.bundleName, pngImg.fileName)
            let keyName = pngImg.isInCarFile ? String(format: "(car)%@", imgName) : imgName
            pngDic.setValue(String(format: "%0.2fK", imgSize), forKey: keyName)
            if imgSize < 10 {
                continue
            }
            index = index + 1
            if index > 100 {
                break
            }
            let childModel = DiagnoseModel.init(title: keyName, subTitle:String(format: ASTextDictionary.valueForKey(key: "diagnoseResultItemRightTitle5"),String(format: "%0.2fK", imgSize)), level: NodeType.Second, diagType: DiagnoseType.UnusedResource)
            childModel.detailData = pngImg.filePath
            modelList.append(childModel)
        }
        // 将结果存文件
        let paths = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true) as NSArray
        let dir = paths.object(at: 0) as! NSString
        let filePath = dir.appendingPathComponent("UnusedRes.plist")
        pngDic.write(toFile: filePath, atomically: false)
        // 写root结点
        let rootModel = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle5"), subTitle: String(format: ASTextDictionary.valueForKey(key: "diagnoseResultTips5"),String(format: "%d个", unusedRes.count),String(format: "%0.2fK", resSize), String(format: "%d",100)), level: NodeType.First, diagType: DiagnoseType.UnusedResource)
        rootModel.childModels = modelList
        rootModel.detailData = filePath
        diagnoseResult.append(rootModel)
        return resSize / 1000.0
    }
    /**
     获取assets外的图片
     */
    func obtainPngOutofAssets()  -> Double {
        let pngSize = Double(self.dataResult?.all.pngSize ?? 0)
        let pngList: Array = self.dataResult?.all.pngFiles as! Array<ASImageFile>
//        pngList = pngList.sorted { img1, img2 in
//            img1.fileName < img2.fileName
//        }
        var modelList = [DiagnoseModel]()
        var index = 0
        let pngDic: NSMutableDictionary = NSMutableDictionary()
        for pngImg in pngList {
            let imgSize = (Double)(pngImg.inputSize) / 1000.0
            let imgName: String = pngImg.bundleName == "main" ? pngImg.fileName : String(format: "%@/%@", pngImg.bundleName, pngImg.fileName)
            pngDic.setValue(String(format: "%0.2fK", imgSize), forKey: imgName)
            if imgSize < 10 {
                continue
            }
            index = index + 1
            if index > 100 {
                break
            }
            let childModel = DiagnoseModel.init(title: imgName, subTitle: String(format: ASTextDictionary.valueForKey(key: "diagnoseResultItemRightTitle4"),String(format: "%0.2fK", imgSize)), level: NodeType.Second, diagType: DiagnoseType.ImageAssets)
            
            childModel.detailData = pngImg.filePath
            modelList.append(childModel)
        }
        // 将结果存文件
        let paths = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true) as NSArray
        let dir = paths.object(at: 0) as! NSString
        let filePath = dir.appendingPathComponent("NotInAssets.plist")
        pngDic.write(toFile: filePath, atomically: false)
        // 写root结点
//        "共检测到%d个图片不在Asset Catalog中，总大小%0.2fK，以下显示前100个"
        let rootModel = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle4"), subTitle: String(format:ASTextDictionary.valueForKey(key: "diagnoseResultTips4"), String(format: "%d", pngList.count),String(format: "%0.2fK", pngSize/1000.0), String(format: "%d", 100)), level: NodeType.First, diagType: DiagnoseType.ImageAssets)
        rootModel.childModels = modelList
        rootModel.detailData = filePath
        diagnoseResult.append(rootModel)
        return pngSize/1000.0/1000.0
    }
    // 获取无用类结果
    func obtainUnusedClasses(appPath: String) -> Double {
        let resData: Array = MachOCheck.scanUnusedClasses(inFile: appPath)
        let unusedList: Set = resData[1] as! Set<String>
        if unusedList.count == 0 {
            return 0.0
        }
        var modelList = [DiagnoseModel]()
        var index = 0
        for className in unusedList {
            index = index + 1
            if index > 100 {
                break
            }
            let childModel = DiagnoseModel.init(title: className , subTitle: "", level: NodeType.Second, diagType: DiagnoseType.UnusedClass)
            modelList.append(childModel)
        }
        let totalSize = resData[2] as! Double
        let rootModel = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle1"), subTitle: String(format:ASTextDictionary.valueForKey(key: "diagnoseResultTips1"), String(format: "%d", unusedList.count),String(format: "%d", 100)), level: NodeType.First, diagType: DiagnoseType.UnusedClass)
//        let rootModel = DiagnoseModel.init(title: "检测无用类", subTitle: String(format: "共检测到%d个无用类，总计:%0.2fK，以下显示前100个，详情见文件", unusedList.count, totalSize), level: NodeType.First, diagType: DiagnoseType.UnusedClass)

        rootModel.detailData = resData[0] as? String
        rootModel.childModels = modelList
        diagnoseResult.append(rootModel)
        return totalSize
    }
    
    /// 获取段迁移结果
    /// - Returns: Void
    func obtainSegmentMigrateResult(appPath: String) -> Double {
        // 获取二进制文件名
        let binaryPath = self.mainBinaryFilePath(appPath: appPath)
        let migsize: CGFloat = MachOCheck.checkTEXTHasMigratedSize(binaryPath)
        if migsize > 0 {
            let childModel = DiagnoseModel.init(title: "检测二进制段迁移", subTitle: String("将__TEXT内的section进行迁移"), level: NodeType.Second, diagType: DiagnoseType.SegmentMigrate)
            let rootModel = DiagnoseModel.init(title: "二进制段迁移", subTitle: String(format: "iOS13以下设备预计可优化%0.2fM", migsize), level: NodeType.First, diagType: DiagnoseType.SegmentMigrate)
            rootModel.childModels = [childModel]
            diagnoseResult.append(rootModel)
        }
        return migsize
    }
    
    /// 获取二进制strip的结果
    /// - Returns: Void
    func obtainStripResult(appPath: String) -> Double {
        // 获取strip二进制结果
        let stripRes: Dictionary = MachOCheck.checkHasStripedFrameworks(appPath)
        if stripRes.count == 0 {
            return 0.0
        }
        var stripList = [DiagnoseModel]()
        var totalSize:CGFloat = 0.00
        for (key,value) in stripRes {
            let childNode = DiagnoseModel.init(title: String(format: "Frameworks/%@", key as! String), subTitle: String(format: ASTextDictionary.valueForKey(key: "diagnoseResultItemRightTitle2"), String(format: "%.2fM", value as! CGFloat)), level: NodeType.Second, diagType: DiagnoseType.StripBinary)
            totalSize = totalSize + (value as! CGFloat)
            stripList.append(childNode)
        }
        let rootNode = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle2"), subTitle:String(format: ASTextDictionary.valueForKey(key: "diagnoseResultTips2"),String(format: "%.2fM", totalSize)), level: NodeType.First, diagType: DiagnoseType.StripBinary)
        rootNode.childModels = stripList
        rootNode.detailData = String(format: "%@/Frameworks", appPath)
        diagnoseResult.append(rootNode)
        return totalSize
    }
    /**
     获取重复资源
     */
    func obtainDuplicateRes() -> Double {
        let dupDic: Dictionary = ASFileManager.duplicateFiles(in: self.dataResult)
        if dupDic.count == 0 {
            return 0.0
        }
//        var dupResArr = dupDic.values
//        dupResArr.sorted { list1, list2 in
//            let bFile1 = list1[0] as? ASBaseFile
//            let bFile2: ASBaseFile = list2[0]
//            bFile1.inputSize < bFile2.inputSize
//        }
        var stripList = [DiagnoseModel]()
        var totalSize:CGFloat = 0.00
        var dupResList  = [Array<String>]()
        for (key,value) in dupDic {
            var resName: String = ""
            let resList = value as? Array<ASBaseFile>
            guard let resList = resList else {
                continue
            }
            var filePaths = [String]()
            var curSize: CGFloat = 0.0
            for baseFile in resList {
                // 拼接资源名称C
                guard let fileName = baseFile.bundleName == "main" ? baseFile.fileName : String(format: "%@/%@", baseFile.bundleName, baseFile.fileName) else { continue }
                filePaths.append(fileName)
                resName.append(String(format:"%@ ", baseFile.fileName))
                totalSize = totalSize + CGFloat(baseFile.inputSize)
                curSize = curSize + CGFloat(baseFile.inputSize)
            }
            dupResList.append(filePaths)
            let childNode = DiagnoseModel.init(title: resName, subTitle:String(format: ASTextDictionary.valueForKey(key: "diagnoseResultItemRightTitle6"),String(format: "%0.2fK", curSize/1000)), level: NodeType.Second, diagType: DiagnoseType.DuplicateRes)
            childNode.detailData = resList[0].filePath
            stripList.append(childNode)
        }
        // 将结果存文件
        // Swfit中的Array和Dictionary是结构体,是值类型, 没有与plist相关的接口, 需要先转换为对应的Objectivc-C类型
        let resArr: NSArray = dupResList as NSArray
        let paths = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true) as NSArray
        let dir = paths.object(at: 0) as! NSString
        let filePath = dir.appendingPathComponent("DuplictateRes.plist")
        resArr.write(toFile: filePath, atomically: false)
        totalSize = totalSize / 1000.0
        let rootNode = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle6"), subTitle: String(format: ASTextDictionary.valueForKey(key: "diagnoseResultTips6"), String(format: "%.2fK", totalSize)), level: NodeType.First, diagType: DiagnoseType.DuplicateRes)
        rootNode.childModels = stripList
        rootNode.detailData = filePath
        diagnoseResult.append(rootNode)
        return totalSize / 1000.0
    }
    
    /**
     LTO检测
     **/
    func obtainLTOResult()  -> Double {
        var stripList = [DiagnoseModel]()
        let childNode = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultItemLeftTitle3"), subTitle: "", level: NodeType.Second, diagType: DiagnoseType.LTO)
        stripList.append(childNode)
        let rootNode = DiagnoseModel.init(title: ASTextDictionary.valueForKey(key: "diagnoseResultTitle3"), subTitle: ASTextDictionary.valueForKey(key: "diagnoseResultTips3"), level: NodeType.First, diagType: DiagnoseType.LTO)
        rootNode.childModels = stripList
        diagnoseResult.append(rootNode)
        return 0.0
    }
    
    /**
     获取APP的可执行文件路径
     */
    func mainBinaryFilePath(appPath: String) -> String {
        // 获取二进制文件名
        let filePath: String = appPath.components(separatedBy: "/").last!
        let fileName: String = filePath.components(separatedBy: ".").first ?? filePath
        return String(format: "%@/%@", appPath, fileName)
    }
}
