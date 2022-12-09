//
//  ASShowFileListCollectionCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListCollectionCell: ASShowFileListBaseCell {
    
    @IBOutlet weak var leftMarginConstraints: NSLayoutConstraint!
    
    @IBOutlet weak var iconImageView: NSImageView!
    
    @IBOutlet weak var titleLabel: NSTextField!
    
    @IBOutlet weak var fileCountLabel: NSTextField!
    
    @IBOutlet weak var fileDescriptionLabel: NSTextField!

    @IBOutlet weak var fileSizeLabel: NSTextField!

    @IBOutlet weak var arrowImageView: NSImageView!

    override func update(model: ASShowFileListBaseModel) {
        guard let collectionModel:ASShowFileListCollectionModel = model as? ASShowFileListCollectionModel else {
            return
        }
        self.leftMarginConstraints.constant = CGFloat(10+20*model.foldLevel)
        self.iconImageView.image = NSImage(named: collectionModel.iconName())
        self.titleLabel.stringValue = collectionModel.fileName
        self.fileCountLabel.stringValue = String(format: "Files Count:  %lu Items", collectionModel.subFilesCount())
        self.fileDescriptionLabel.stringValue = String(format: "Desc:  %@", collectionModel.fileDiscription)
        self.fileSizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: collectionModel.fileSize))
        self.model = model;
        
        if (model.isFold) {
            self.arrowImageView.image = NSImage(named:"as_arrow_right");
        }else{
            self.arrowImageView.image = NSImage(named:"as_arrow_down");
        }
        
    }
    
    override class func cellHeight(model: ASShowFileListBaseModel) -> CGFloat {
        return 120
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        // Drawing code here.
    }
    
}
