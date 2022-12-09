//
//  ChildDiagnoseCellView.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/22.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

protocol ChildCellDelegate: NSObject {
    func cellClicked(filePath: String)
}

class ChildDiagnoseCellView: NSTableCellView ,NibLoadable, DiagCellProtocol {

    @IBOutlet weak var titleTextField: NSTextField!
    @IBOutlet weak var subtitleTextField: NSTextField!
    @IBOutlet weak var fileBtn: NSButton!
    weak var delegate:ChildCellDelegate?;
    var model: DiagnoseModel!

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
//        self.layer?.backgroundColor = NSColor.green.cgColor

    }
    
    @IBAction func buttonClicked(_ sender: NSButton) {
        if model.detailData != nil {
            self.delegate?.cellClicked(filePath: model.detailData as! String)
        }
    }
    
    func configCellView(model: DiagnoseModel) -> Void {
        self.model = model
        titleTextField.stringValue = model.title
        subtitleTextField.stringValue = model.subTitle
        // 添加一个透明button
//        if model.diagType == DiagnoseType.UnusedResource {
            let fr = fileBtn.frame
            fileBtn.frame = NSRect.init(x: 0, y: 0, width: fr.size.width, height:40)
//        }
    }
}
