//
//  ASShowFileListBaseCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

protocol ASShowFileListCellProtocol{
    static func cellHeight(model:ASShowFileListBaseModel)->CGFloat
}

class ASShowFileListBaseCell: PXListViewCell,ASShowFileListCellProtocol {
    var model:ASShowFileListBaseModel?
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        // Drawing code here.
    }
    func update(model:ASShowFileListBaseModel){
        
    }
    class func cellHeight(model:ASShowFileListBaseModel)->CGFloat{
        return 50
    }
    
}
