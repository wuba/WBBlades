//
//  DiagnoseItemCellView.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/9.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

protocol DiagnoseCellDelegate: NSObject {
    func textMigrateConfig()
    func ltoConfig()
    func locationDirConfig(filePath: String);
    func stripConfig()

}

class DiagnoseItemCellView: NSTableCellView, NibLoadable, DiagCellProtocol {
    static let iconList : [String] = ["as_icon_collection_macho", "as_icon_collection_macho", "as_icon_collection_img", "as_icon_collection_assets","as_icon_collection_others","as_icon_collection_macho","as_icon_collection_others","as_icon_collection_others"]
    
    static let chbtnTitles : [String] = ["进入优化", "查看配置", "查看文件", "查看文件","查看文件","查看配置","查看文件","查看文件"]

    static let enbtnTitles : [String] = ["Enter optimization", "View Configuration", "View File", "View File","View File","View Configuration","View File","View File"]

    static var btnTitles : [String] {
        get {
            return ASTextDictionary.mode == .english ? DiagnoseItemCellView.enbtnTitles : DiagnoseItemCellView.chbtnTitles
        }
    }
    var itemType: DiagnoseType!
    weak var delegate:DiagnoseCellDelegate?;

    @IBOutlet weak var iconImageView: NSImageView!
    @IBOutlet weak var titleTextField: NSTextField!
    @IBOutlet weak var subTitleTextField: NSTextField!
    @IBOutlet weak var handleBtn: NSButton!
    var model: DiagnoseModel!
    
    @IBAction func handleOptimize(_ sender: NSButton) {
        switch model.diagType {
        case .UnusedClass,.ImageAssets,.UnusedResource,.ImageCompress,.DuplicateRes:
            self.delegate?.locationDirConfig(filePath: model.detailData as! String)
        case .SegmentMigrate:
            self.delegate?.textMigrateConfig()
        case .LTO:
            self.delegate?.ltoConfig()
        case .StripBinary:
            self.delegate?.stripConfig()
        default: break
            
        }
    }
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
//        self.layer?.backgroundColor = NSColor.yellow.cgColor

        // Drawing code here.
    }
    func configCellView(model: DiagnoseModel) -> Void {
        self.model = model
        handleBtn.title = DiagnoseItemCellView.btnTitles[model.diagType.rawValue]
        iconImageView.image = NSImage(named: DiagnoseItemCellView.iconList[model.diagType.rawValue])
        titleTextField.stringValue = model.title
        subTitleTextField.stringValue = model.subTitle
    }

}
