//
//  GPTMessageCell.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/7.
//

import Cocoa

class GPTMessageCell: NSTableCellView, NibLoadable {

    @IBOutlet weak var roleImgView: NSImageView!
    
    @IBOutlet weak var msgContentView: NSTextField!
    
    @IBOutlet weak var labelHeightConstraint: NSLayoutConstraint!
    var msgModel: Message!

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        
        // Drawing code here.
    }
    
    func configCellView(model: Message) -> Void {
        self.msgModel = model
        if (model.baseReqMsg.role == "assistant") {
            roleImgView.image = NSImage(named: "openai")
//            let customGray = NSColor(calibratedWhite: 0.9, alpha: 0.6)
            let customGray = NSColor(red: 245/255, green: 245/255, blue: 245/255, alpha: 1)
            self.layer?.backgroundColor = customGray.cgColor
        }
        else {
            roleImgView.image = NSImage(named: "person")
            self.layer?.backgroundColor = NSColor.white.cgColor
        }
        msgContentView.stringValue = self.msgModel.messageContent
        // 如果是报错，则标为红色
        if self.msgModel.responseError == nil {
            msgContentView.textColor = NSColor.black
        } else {
            msgContentView.textColor = NSColor.red
        }
        labelHeightConstraint.constant = self.msgModel.textHeight
    }

    
}
