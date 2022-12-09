//
//  ASFileCell.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/8.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASFileCell: PXListViewCell {
    var currentFile: ASShowFileListBaseModel?

    
    @IBOutlet weak var iconView: NSImageView!
    @IBOutlet weak var nameLabel: NSTextField!
    @IBOutlet weak var sizeLabel: NSTextField!
    @IBOutlet weak var instructionLabel: NSTextField!
    @IBOutlet weak var extraLabel: NSTextField!
    @IBOutlet weak var foldArrow: NSButton!
    var arrowRotate:CGFloat = 0;
    
    
    override var row: UInt{
        get {
            return super.row
        }
        set(newRow){
            super.row = newRow
        }
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        // Drawing code here.
        if((self.currentFile?.isFold ?? true) == false){
            NSColor.selectedControlColor.set()
        }else{
            NSColor.white.set()
        }
        //Draw the border and background
        let roundedRect = NSBezierPath(roundedRect: self.bounds, xRadius: 6.0, yRadius: 6.0)
        roundedRect.fill()
    }
    
    
    func config(fold:Bool){
        var targetRotate = 0.0
        if (fold == true) {
            targetRotate = 0.0
        }else{
            targetRotate = 90.0
        }
        self.foldArrow.rotate(byDegrees: targetRotate - self.arrowRotate)
        self.arrowRotate += (targetRotate - self.arrowRotate)
    }
    
    
    func configFile(file:ASShowFileListBaseModel?){
        self.currentFile = file
        var subItemCount = file?.subFiles().count ?? 0 ;
        if (subItemCount == 0) {
            subItemCount = 1
        }
        self.nameLabel.stringValue = String(format: "%@ (%d items)", file?.fileName ?? "unknow",subItemCount)
        self.sizeLabel.stringValue = String(format: "%@", ASUtils.discription(withByteSize: file?.fileSize ?? 0))
        self.instructionLabel.stringValue = file?.fileDiscription ?? ""
        self.extraLabel.stringValue = file?.subDiscription ?? ""
        self.config(fold: file?.isFold ?? true)
        self.iconView.image = NSImage(named:file?.iconName() ?? "as_icon_otherfiles")
    }
    
}
