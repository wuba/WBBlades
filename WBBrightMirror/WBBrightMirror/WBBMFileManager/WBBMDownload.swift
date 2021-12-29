//
//  WBDownloadTools.swift
//  Pods-WBBladesCrashAnalyzeApp
//
//  Created by 朴惠姝 on 2021/4/22.
//

import Foundation

class WBBMDownload {
    
    static let downloadPath = String.init(format: "%@%@", NSSearchPathForDirectoriesInDomains(.downloadsDirectory, .userDomainMask, true).first ?? "","/WBBrightMirror")
}
