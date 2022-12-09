//
//  ASShowFileListAssetLoadingStatusModel.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/23.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

enum ASShowFileListAssetLoadingStatusType: Int{
    case  loading,error,finished
}
class ASShowFileListAssetLoadingStatusModel: ASShowFileListBaseModel {
    var loadingStatus: ASShowFileListAssetLoadingStatusType = .loading
}
