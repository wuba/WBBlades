//
//  ASShowFileListAssetModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListAssetModel: ASShowFileListBaseModel {
    var originData:ASCarFile?
    var imgs:[ASShowFileListImageModel] = []
    
    let loadingModel:ASShowFileListAssetLoadingStatusModel = {
        return ASShowFileListAssetLoadingStatusModel()
    }()
    
    private var _fileSize: UInt = 0
    
    override var fileSize: UInt {
        get {
            return self._fileSize
        }
        set {
            self._fileSize = newValue
            self.subDiscription = "文件大小:"+ASUtils.discription(withByteSize: self._fileSize)
        }
    }
    
    convenience init(carFile:ASCarFile) {
        self.init();
        self.fileName = carFile.fileName
        self.fileDiscription = "资源压缩包"
        self.filePath = carFile.filePath
        self.originData = carFile
        self.fileSize = carFile.inputSize
        let hasCarLoaded = carFile.hasLoaded
        if (hasCarLoaded){
            let imgFiles:[ASImageFile] = carFile.images as? [ASImageFile] ?? []
            for imgFile in imgFiles {
                let file = ASShowFileListImageModel(imgFile: imgFile)
                self.imgs.append(file)
            }
            self.fileSize = self.originData?.strippedSize ?? 0
        }
        NotificationCenter.default.addObserver(self, selector: #selector(self.dataUpdate), name: NSNotification.Name.asFileUpdate, object: carFile)
    }
    
    override func subFilesCount()->UInt{
        let hasCarLoaded = self.originData?.hasLoaded ?? false
        if (hasCarLoaded){
            return UInt(self.imgs.count)
        }
        return 0
    }
    
    
    override func subFiles()->[ASShowFileListBaseModel]{
        if (self.isFold){
            return []
        }
        let hasCarLoaded = self.originData?.hasLoaded ?? false
        if (hasCarLoaded){
            return self.imgs
        }else{
            self.originData?.unzipCarFile({
                let imgFiles:[ASImageFile] = self.originData?.images as? [ASImageFile] ?? []
                for imgFile in imgFiles {
                    let file = ASShowFileListImageModel(imgFile: imgFile)
                    self.imgs.append(file)
                }
                self.fileSize = self.originData?.strippedSize ?? 0
            })
        }
        return [self.loadingModel]
    }
    
    override func iconName() -> String {
        return "as_icon_assets"
    }
    override func cellHeight ()->CGFloat{
        return ASShowFileListAssetCell.cellHeight(model: self)
    }
    override func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        let reusableIdentifier = "ASShowFileListAssetCell"
        var cell = listView.dequeueCell(withReusableIdentifier: reusableIdentifier);
        if cell == nil {
            cell = (ASShowFileListAssetCell.cellLoaded(fromNibNamed: reusableIdentifier, reusableIdentifier: reusableIdentifier) as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListAssetCell
        ascell?.update(model: self)
        return ascell
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    @objc func dataUpdate(noti:Notification){
        let imgFiles:[ASImageFile] = self.originData?.images as? [ASImageFile] ?? []
        let type:NSString = noti.userInfo?[kASCarFileNotificationUserInfoUpdateTypeKey] as? NSString ?? kASCarFileUpdateTypeImages as NSString
        if (type.isEqual(to: kASCarFileUpdateTypeImages)) {
            self.imgs = []
            for imgFile in imgFiles {
                let file = ASShowFileListImageModel(imgFile: imgFile)
                self.imgs.append(file)
            }
        }
    }
}
