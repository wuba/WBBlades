//
//  GPTMsgDataService.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/7.
//

import Foundation

struct GPTMsgDataService: BaseDataService {
    private let fileName = "messages"
    
    var dataURL: URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        var documentURL = paths[0]
        documentURL.appendPathComponent(fileName)
        return documentURL
    }
}
