//
//  SizeProfileModel.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/3/1.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

enum ItemType: Int {
    case EXEBinary = 0, ImageInAssets, ImageOutofAssets, OtherRes
}

class SizeProfileModel: NSObject {
    
    static let chNameList : [String] = ["二进制", "Assets", "Assets外图片", "其它资源"]
    
    static let enNameList : [String] = ["Binary", "Assets", "PNG Files outside Assets", "Other Type Files"]

    static var nameList : [String]
    {
        get{
            return ASTextDictionary.mode == .english ? SizeProfileModel.enNameList : SizeProfileModel.chNameList
        }
    }
    
    static let colorList : [String] = ["44DDFF", "FF6450", "7359FF", "3CFF7E"]
//    static let colorList : [String] = ["44DDFF", "FF6450", "7359FF", "F9FF43", "3CFF7E"]

    var itemSize : UInt
    var iconName : String?
    var profileDetail : Dictionary<String,NSNumber>?
    var itype : ItemType
    
    lazy var itemName: String = {
        return SizeProfileModel.nameList[self.itype.rawValue]
    }()
    lazy var itemColor: String = {
        return SizeProfileModel.colorList[self.itype.rawValue]
    }()
    init(itype : ItemType, itemSize : UInt) {
        self.itype = itype
        self.itemSize = itemSize
    }
    
}
