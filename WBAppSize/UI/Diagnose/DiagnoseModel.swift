//
//  DiagnoseModel.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/22.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

enum NodeType: Int {
    case First = 1, Second
}

enum DiagnoseType: Int {
    case StripBinary = 0, SegmentMigrate, ImageCompress, ImageAssets, UnusedResource, LTO, UnusedClass, DuplicateRes
}

class DiagnoseModel: NSObject {
    var title : String!
    var subTitle : String!
    var level : NodeType!
    var diagType : DiagnoseType!
    var childModels : [DiagnoseModel]?
    var detailData: Any?
    
    init(title : String, subTitle : String, level:NodeType, diagType : DiagnoseType) {
        self.title = title
        self.subTitle = subTitle
        self.level = level
        self.diagType = diagType
    }
}
