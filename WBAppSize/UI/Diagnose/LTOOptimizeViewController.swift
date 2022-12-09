//
//  LTOOptimizeViewController.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/4/8.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class LTOOptimizeViewController: NSViewController {

    @IBOutlet var LTOOptimizeDescText: NSTextField!
    
    @IBOutlet var LTOOptimizeDescSubText1: NSTextField!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
        LTOOptimizeDescText.stringValue = ASTextDictionary.valueForKey(key: "LTOOptimizeDescContent")
        LTOOptimizeDescText.stringValue = ASTextDictionary.valueForKey(key: "LTOOptimizeDescSubContent1")
        
    }
    
}
