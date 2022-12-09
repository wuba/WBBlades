//
//  ASShowFileListBaseModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListBaseModel: NSObject {
    var fileName: String = ""
    var fileDiscription: String = ""
    var subDiscription: String?
    var filePath: String?
    var fileSize: UInt = 0
    var isFold: Bool = true
    var foldLevel: UInt = 0
    
    func subFilesCount()->UInt{
        return UInt(self.subFiles().count)
    }
    
    func subFiles()->[ASShowFileListBaseModel]{
        return []
    }
        
    func iconName()->String{
        return "as_icon_other"
    }
    
    func cellHeight ()->CGFloat{
        return ASShowFileListBaseCell.cellHeight(model: self)
    }
    
    func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        var cell = listView.dequeueCell(withReusableIdentifier: "ASShowFileListBaseCell");
        if cell == nil {
            cell = (ASShowFileListBaseCell.cellLoaded(fromNibNamed: "ASShowFileListBaseCell", reusableIdentifier: "ASShowFileListBaseCell") as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListBaseCell
        ascell?.update(model: self)
        return ascell
    }
}
