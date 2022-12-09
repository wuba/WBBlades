//
//  ASFileModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/8.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASFileModel: NSObject {
    static func readFilesFrom(mainBundle:ASMainBundle)->[ASShowFileListBaseModel]{
        var asFileModel:[ASShowFileListBaseModel] = []
        
        let machOCollection = ASShowFileListCollectionModel(machOFiles: mainBundle.all.machOFiles as? [ASMachOFile] ?? [])
        asFileModel.append(machOCollection)
        
        let carCollection = ASShowFileListCollectionModel(carFiles: mainBundle.all.carFiles as? [ASCarFile] ?? [])
        asFileModel.append(carCollection);
        
        let pngCollection = ASShowFileListCollectionModel(imgFiles: mainBundle.all.pngFiles as! [ASImageFile])
        asFileModel.append(pngCollection);

        let otherCollection = ASShowFileListCollectionModel(other: mainBundle)
        asFileModel.append(otherCollection);
        return asFileModel
    }
}
