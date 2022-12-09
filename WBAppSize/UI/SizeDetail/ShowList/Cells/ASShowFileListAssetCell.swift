//
//  ASShowFileListAssetCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListAssetCell: ASShowFileListBaseCell {

    @IBOutlet weak var leftMarginConstraint: NSLayoutConstraint!
    
    @IBOutlet weak var iconImageView: NSImageView!
    
    @IBOutlet weak var titleLabel: NSTextField!
    
    @IBOutlet weak var fileCountLabel: NSTextField!
    
    @IBOutlet weak var fileSizeLabel: NSTextField!
    
    @IBOutlet weak var optimizedCountLabel: NSTextField!
    
    @IBOutlet weak var totalCountLabel: NSTextField!
    
    @IBOutlet weak var arrowImageView: NSImageView!

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    override func update(model: ASShowFileListBaseModel) {
        NotificationCenter.default.removeObserver(self)
        guard let assetModel:ASShowFileListAssetModel = model as? ASShowFileListAssetModel else {
            return
        }
        self.reload(model: assetModel)
        self.model = assetModel
        NotificationCenter.default.addObserver(self, selector: #selector(self.dataUpdate), name: NSNotification.Name.asFileUpdate, object: assetModel.originData)
    }
    
    func reload(model:ASShowFileListBaseModel?) {
        guard let assetModel:ASShowFileListAssetModel = model as? ASShowFileListAssetModel else {
            return
        }
        self.leftMarginConstraint.constant = CGFloat(10+20*assetModel.foldLevel);
        self.iconImageView.image = NSImage(named: assetModel.iconName())
        self.titleLabel.stringValue = assetModel.fileName
        self.fileSizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: assetModel.fileSize))
        
        if (assetModel.originData?.hasLoaded ?? false) {
            self.fileCountLabel.stringValue = String(format: "Files Count:  %lu Items", assetModel.subFilesCount())
            self.optimizedCountLabel.stringValue = String(format: "%lu", assetModel.subFilesCount())
            self.totalCountLabel.stringValue = String(format: "%lu", assetModel.subFilesCount())
        }else{
            self.fileCountLabel.stringValue = "Data loading..."
            self.optimizedCountLabel.stringValue = "0"
            self.totalCountLabel.stringValue = "0"
        }
        if (assetModel.isFold) {
            self.arrowImageView.image = NSImage(named:"as_arrow_right");
        }else{
            self.arrowImageView.image = NSImage(named:"as_arrow_down");
        }
    }
    
    @objc func dataUpdate() {
        self.reload(model: self.model)
    }
    
    override class func cellHeight(model: ASShowFileListBaseModel) -> CGFloat {
        return 90
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        // Drawing code here.
    }
    
}
