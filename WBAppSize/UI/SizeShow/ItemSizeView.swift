//
//  ItemSizeView.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/3.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa


protocol ItemSizeViewDelegate: NSObject {
    func itemSizeViewClicked(item:SizeProfileModel?) -> Void;
}

class ItemSizeView: NSView, NibLoadable{
    @IBOutlet weak var itemSize: NSTextField!
    @IBOutlet weak var itemName: NSTextField!
    
    weak var delegate:ItemSizeViewDelegate?;
    
    var profileModel:SizeProfileModel?
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)

        // Drawing code here.
    }
    
   func configItem(sizeItem : SizeProfileModel) -> Void {
        self.wantsLayer = true;
       self.layer?.backgroundColor = NSColor.fromHexString(sizeItem.itemColor, alpha: 1)?.cgColor
//       self.itemSize.stringValue = String(format: "%.2f", Double(sizeItem.itemSize)/1024.0/1024.0).appending("M")
//        self.itemName.stringValue = sizeItem.itemName
       self.profileModel = sizeItem;
    }
    
    @IBAction func didClick(_ sender: Any) {
        self.delegate?.itemSizeViewClicked(item: self.profileModel);
    }
    
}

