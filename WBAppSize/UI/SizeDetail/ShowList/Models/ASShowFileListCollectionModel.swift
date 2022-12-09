//
//  ASShowFileListCollectionModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

enum ASShowFileListCollectionFileType: Int{
    case  other = 0, car, macho, img
}

class ASShowFileListCollectionModel: ASShowFileListBaseModel {
    var childFiles: [ASShowFileListBaseModel] = []
    var fileType: ASShowFileListCollectionFileType = .other
  
    override func subFilesCount()->UInt{
        return UInt(self.childFiles.count)
    }
    
    override func subFiles()->[ASShowFileListBaseModel]{
        if self.isFold {
            return []
        }
        return self.childFiles
    }
    
    //mach-o 文件合集
    convenience init(machOFiles:[ASMachOFile]) {
        self.init();
        self.fileType = .macho;
        for machOFile in machOFiles {
            let file = ASShowFileListMachOModel(machOFile: machOFile)
            self.childFiles.append(file)
            self.fileSize += file.fileSize
        }
        self.fileName = ASTextDictionary.valueForKey(key: "packetSizeDetialItemTitleBinary")
        self.fileDiscription = ASTextDictionary.valueForKey(key: "packetSizeDetialItemDescBinary")
    }
    //car 文件合集
    convenience init(carFiles:[ASCarFile]) {
        self.init();
        self.fileType = .car;
        for carFile in carFiles {
            let file = ASShowFileListAssetModel(carFile: carFile)
            self.childFiles.append(file)
            self.fileSize += file.fileSize
        }
        self.fileName = ASTextDictionary.valueForKey(key: "packetSizeDetailItemTitleCar")
        self.fileDiscription = ASTextDictionary.valueForKey(key: "packetSizeDetailItemDescCar")
    }
    //png 文件合集
    convenience init(imgFiles:[ASImageFile]) {
        self.init();
        self.fileType = .img;
        for imgFile in imgFiles {
            let file = ASShowFileListImageModel(imgFile: imgFile)
            self.childFiles.append(file)
            self.fileSize += file.fileSize
        }
        self.fileName = ASTextDictionary.valueForKey(key: "packetSizeDetailItemTitlePNG")
        self.fileDiscription = ASTextDictionary.valueForKey(key: "packetSizeDetailItemDescPNG")
    }
    //other 文件合集
    convenience init(other mainBundle:ASMainBundle) {
        self.init();
        self.fileType = .other;
        self.fileSize = 0
        //plistFlies文件
        for plistFlie in mainBundle.all.plistFlies as! [ASBaseFile] {
            self.childFiles.append(ASShowFileListOtherModel(otherFile: plistFlie ))
        }
        self.fileSize += mainBundle.all.plistSize
        //json文件
        for jsonFile in mainBundle.all.jsonFiles as! [ASBaseFile] {
            self.childFiles.append(ASShowFileListOtherModel(otherFile: jsonFile ))
        }
        self.fileSize += mainBundle.all.jsonSize
        //jpg文件
        for jpgFile in mainBundle.all.jpgFiles as! [ASBaseFile] {
            self.childFiles.append(ASShowFileListOtherModel(otherFile: jpgFile ))
        }
        self.fileSize += mainBundle.all.jpgSize
        //nib文件
        for nibFile in mainBundle.all.nibFiles as! [ASBaseFile] {
            self.childFiles.append(ASShowFileListOtherModel(otherFile: nibFile ))
        }
        self.fileSize += mainBundle.all.nibSize
        //其他文件
        for otherFile in mainBundle.all.otherFiles as! [ASBaseFile] {
            self.childFiles.append(ASShowFileListOtherModel(otherFile: otherFile ))
        }
        self.fileSize += mainBundle.all.otherSize
        
        self.fileName = ASTextDictionary.valueForKey(key: "packetSizeDetailItemTitleOther")
        self.fileDiscription = ASTextDictionary.valueForKey(key: "packetSizeDetailItemDescOther")
    }
    
    override func iconName()->String{
        switch self.fileType {
            case .macho:
            return "as_icon_collection_macho"
            case .img:
            return "as_icon_collection_img"
            case .car:
            return "as_icon_collection_assets"
            case .other:
            return "as_icon_collection_others"
        }
    }
    override func cellHeight ()->CGFloat{
        return ASShowFileListCollectionCell.cellHeight(model: self)
    }
    override func cellFor(listView:PXListView)->ASShowFileListBaseCell? {
        let reusableIdentifier = "ASShowFileListCollectionCell"
        var cell = listView.dequeueCell(withReusableIdentifier: reusableIdentifier);
        if cell == nil {
            cell = (ASShowFileListCollectionCell.cellLoaded(fromNibNamed: reusableIdentifier, reusableIdentifier: reusableIdentifier) as! PXListViewCell)
        }
        let ascell = cell as? ASShowFileListCollectionCell
        ascell?.update(model: self)
        return ascell
    }
}
