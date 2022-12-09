//
//  TextDictionary.swift
//  WBBladesCrashApp
//
//  Created by wbblades on 2022/1/13.
//  Copyright © 2022 58.com. All rights reserved.
//

import Foundation
import AppKit
import WBAppSize
enum Language: NSInteger{
    case chinese = 0
    case english
}
class TextDictionary {
    static var _mode: Language?
    static var mode: Language{
        set{
            _mode = newValue
            var languageKey = ""
            switch (newValue){
            case .chinese:
                languageKey = "chinese"
                ASTextDictionary.mode = .chinese
                break
            case .english:
                languageKey = "eng"
                ASTextDictionary.mode = .english
                break
            }
            self.languageKey = languageKey
        }
        get{
            return _mode ?? .chinese
        }
    }
    static var languageKey: String = "chinese"
    static var textDictionary: Dictionary<String,Any>?
    
    class func valueForKey(key: String) -> String{
        if (textDictionary == nil){
            let path = Bundle.main.path(forResource: "LanguageText", ofType: "plist") ?? ""
            let textDic = NSDictionary.init(contentsOfFile: path) as? Dictionary <String,Any>
            textDictionary = textDic
        }
        
        guard let textDic = textDictionary else{
            return ""
        }
        
        if let keyDic = textDic[key] as? Dictionary<String, String>,let textString = keyDic[languageKey]{
            return textString
        }
        
        return ""
    }
}
