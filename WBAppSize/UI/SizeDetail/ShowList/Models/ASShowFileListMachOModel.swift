//
//  ASShowFileListMachOModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListMachOModel: ASShowFileListBaseModel {
    var originData:ASMachOFile?
    convenience init(machOFile:ASMachOFile) {
        self.init();
        self.fileName = machOFile.fileName
        self.fileDiscription = "二进制文件"
        self.fileSize = machOFile.inputSize
        self.filePath = machOFile.filePath
        self.subDiscription = machOFile.mainSegmentSizeDiscription()
        self.originData = machOFile;
    }
    
    override func iconName()->String{
        return "as_icon_macho"
    }
    override func cellHeight ()->CGFloat{
        return ASShowFileListMachOCell.cellHeight(model: self)
    }
    override func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        let reusableIdentifier = "ASShowFileListMachOCell"
        var cell = listView.dequeueCell(withReusableIdentifier: reusableIdentifier);
        if cell == nil {
            cell = (ASShowFileListMachOCell.cellLoaded(fromNibNamed: reusableIdentifier, reusableIdentifier: reusableIdentifier) as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListMachOCell
        ascell?.update(model: self)
        return ascell
    }
}
