//
//  ASShowFileListOtherCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListOtherCell: ASShowFileListBaseCell {

    
    @IBOutlet weak var leftMarginConstraint: NSLayoutConstraint!
    
    @IBOutlet weak var iconImageView: NSImageView!
    
    @IBOutlet weak var titleLabel: NSTextField!
    
    @IBOutlet weak var fileTypeLabel: NSTextField!
    
    @IBOutlet weak var fileSizeLabel: NSTextField!
    
    override func update(model: ASShowFileListBaseModel) {
        guard let otherModel:ASShowFileListOtherModel = model as? ASShowFileListOtherModel else {
            return
        }
        self.leftMarginConstraint.constant = CGFloat(50+20*otherModel.foldLevel);
        self.iconImageView.image = NSImage(named: otherModel.iconName())
        self.titleLabel.stringValue = otherModel.fileName
        self.fileTypeLabel.stringValue = String(format: "%@",otherModel.originData?.fileType ?? "unknow")
        self.fileSizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: otherModel.fileSize))
    }
    
    override class func cellHeight(model: ASShowFileListBaseModel) -> CGFloat {
        return 85
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        // Drawing code here.
    }
    
}
