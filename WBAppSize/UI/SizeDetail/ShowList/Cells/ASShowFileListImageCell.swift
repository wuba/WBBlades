//
//  ASShowFileListImageCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListImageCell: ASShowFileListBaseCell {

    
    @IBOutlet weak var leftMarginConstraint: NSLayoutConstraint!
    
    @IBOutlet weak var iconImageView: NSImageView!
    
    @IBOutlet weak var titleLabel: NSTextField!
    
    @IBOutlet weak var titleExtraLabel: NSTextField!
            
    @IBOutlet weak var fileSizeLabel: NSTextField!
    
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    @objc func dataUpdate() {
        self.reload(model: self.model)
    }
    
    override func update(model: ASShowFileListBaseModel) {
        guard let imgModel:ASShowFileListImageModel = model as? ASShowFileListImageModel else {
            return
        }
        NotificationCenter.default.removeObserver(self)
        self.reload(model: imgModel)
        self.model = imgModel
        NotificationCenter.default.addObserver(self, selector: #selector(self.dataUpdate), name: NSNotification.Name.asFileUpdate, object: imgModel.originData)
    }

    func reload(model:ASShowFileListBaseModel?) {
        guard let imgModel:ASShowFileListImageModel = model as? ASShowFileListImageModel else {
            return
        }
        self.leftMarginConstraint.constant = CGFloat(50+20*imgModel.foldLevel);
        var sizeFontSize = 30.0 - CGFloat(imgModel.foldLevel * 5)
        if (sizeFontSize < 17.0){
            sizeFontSize = 17.0
        }
        self.fileSizeLabel.font = NSFont.boldSystemFont(ofSize: sizeFontSize)
        self.iconImageView.image = NSImage(named: imgModel.iconName())
        self.titleLabel.stringValue = imgModel.fileName
        self.fileSizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: imgModel.fileSize))
        let isCarFile = imgModel.originData?.car_isCarFile ?? false
        if (isCarFile) {
            titleExtraLabel.isHidden = false;
        }else{
            titleExtraLabel.isHidden = true;
        }
    }
    
    override class func cellHeight(model: ASShowFileListBaseModel) -> CGFloat {
        return 105
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        // Drawing code here.
    }
    
}
