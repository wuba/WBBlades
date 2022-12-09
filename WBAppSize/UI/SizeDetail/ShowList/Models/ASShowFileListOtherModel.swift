//
//  ASShowFileListOtherModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListOtherModel: ASShowFileListBaseModel {
    var originData:ASBaseFile?
    convenience init(otherFile:ASBaseFile) {
        self.init();
        self.fileName = otherFile.fileName
        self.fileDiscription = "资源文件"
        self.fileSize = otherFile.inputSize
        self.filePath = otherFile.filePath
        self.subDiscription = "文件大小:"+ASUtils.discription(withByteSize: self.fileSize)
        self.originData = otherFile;
    }
    
    override func iconName() -> String {
        return "as_icon_other"
    }
    override func cellHeight ()->CGFloat{
        return ASShowFileListOtherCell.cellHeight(model: self)
    }
    override func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        let reusableIdentifier = "ASShowFileListOtherCell"
        var cell = listView.dequeueCell(withReusableIdentifier: reusableIdentifier);
        if cell == nil {
            cell = (ASShowFileListOtherCell.cellLoaded(fromNibNamed: reusableIdentifier, reusableIdentifier: reusableIdentifier) as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListOtherCell
        ascell?.update(model: self)
        return ascell
    }
}
