//
//  ASShowFileListMachOCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASShowFileListMachOCell: ASShowFileListBaseCell {

    @IBOutlet weak var leftMarginConstraint: NSLayoutConstraint!
    
    @IBOutlet weak var iconImageView: NSImageView!
    
    @IBOutlet weak var titleLabel: NSTextField!
    
    @IBOutlet weak var fileSizeLabel: NSTextField!
    
    var machoInfoLabels:[NSTextField] = []
    
    
    static let subLabelHeight:CGFloat = 20
    static let subLabelMarginBottom:CGFloat = 15


    override func update(model: ASShowFileListBaseModel) {

        guard let machoModel:ASShowFileListMachOModel = model as? ASShowFileListMachOModel else {
            return
        }
        self.leftMarginConstraint.constant = CGFloat(50+20*model.foldLevel);
        self.iconImageView.image = NSImage(named: machoModel.iconName())
        self.titleLabel.stringValue = machoModel.fileName
        self.fileSizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: machoModel.fileSize))

        
        for label in self.machoInfoLabels {
            label.isHidden = true
        }
        var index = 0;
        let cellHeight = ASShowFileListMachOCell.cellHeight(model: machoModel)
        let top = cellHeight - (15 + 30 + 15) - ASShowFileListMachOCell.subLabelHeight
        for key in (machoModel.originData?.mainSegmentInfo.allKeys ?? []) {
            var subDiscriptionLabel:NSTextField;
            if (index<self.machoInfoLabels.count){
                subDiscriptionLabel = self.machoInfoLabels[index]
            }else{
                subDiscriptionLabel = NSTextField()
                subDiscriptionLabel.font = NSFont.systemFont(ofSize: 15)
                subDiscriptionLabel.textColor = NSColor.black
                subDiscriptionLabel.isEditable = false
                self.addSubview(subDiscriptionLabel)
                subDiscriptionLabel.isBordered = false
                self.machoInfoLabels.append(subDiscriptionLabel)
            }
            subDiscriptionLabel.isHidden = false
            let y = Int(top) - (index * Int(ASShowFileListMachOCell.subLabelHeight))
            subDiscriptionLabel.frame = NSRect(x: Int(50+20*model.foldLevel),
                                               y:y,
                                               width: 99999,
                                               height: 20)
            let segmentName:NSString = key as? NSString ?? ""
            let segmentSize:NSNumber = (machoModel.originData?.mainSegmentInfo[key] as? NSNumber) ?? NSNumber(value: 0)
            subDiscriptionLabel.stringValue = String(format: "%@:%@", segmentName,ASUtils.discription(withByteSize: segmentSize.uintValue))
            index += 1
        }
        
    }
    
    override class func cellHeight(model:ASShowFileListBaseModel)->CGFloat{
        guard let machoModel:ASShowFileListMachOModel = model as? ASShowFileListMachOModel else {
            return 0
        }
        var bottom:CGFloat = 0;
        if (machoModel.originData?.mainSegmentInfo.count ?? 0>0){
            bottom = CGFloat(ASShowFileListMachOCell.subLabelMarginBottom);
        }
        return CGFloat(15 + 30 + 15 + CGFloat(ASShowFileListMachOCell.subLabelHeight) * CGFloat(machoModel.originData?.mainSegmentInfo.count ?? 0) + bottom)
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        // Drawing code here.
    }

    
}
