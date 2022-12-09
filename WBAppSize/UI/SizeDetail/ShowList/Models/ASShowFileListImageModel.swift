//
//  ASShowFileListImageModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListImageModel: ASShowFileListBaseModel {
    var originData:ASImageFile?
    convenience init(imgFile:ASImageFile) {
        self.init();
        self.fileName = imgFile.fileName
        self.fileDiscription = "图片资源"
        if(imgFile.car_isCarFile){
            self.fileSize = imgFile.car_size
        }else{
            self.fileSize = imgFile.inputSize
        }
        self.filePath = imgFile.filePath
        self.subDiscription = "文件大小:"+ASUtils.discription(withByteSize: self.fileSize)
        self.originData = imgFile;
    }
    
    override func iconName()->String{
        return "as_icon_img"
    }
    
    override func cellHeight ()->CGFloat{
        return ASShowFileListImageCell.cellHeight(model: self)
    }
    override func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        let reusableIdentifier = "ASShowFileListImageCell"
        var cell = listView.dequeueCell(withReusableIdentifier: reusableIdentifier);
        if cell == nil {
            cell = (ASShowFileListImageCell.cellLoaded(fromNibNamed: reusableIdentifier, reusableIdentifier: reusableIdentifier) as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListImageCell
        ascell?.update(model: self)
        return ascell
    }
}
