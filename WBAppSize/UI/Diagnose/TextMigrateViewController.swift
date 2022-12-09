//
//  TextMigrateViewController.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/4/1.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class TextMigrateViewController: NSViewController {

    @IBOutlet var textMigrateDescText: NSTextField!
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
        textMigrateDescText.stringValue = ASTextDictionary.valueForKey(key: "textMigrateDescContent")
    }
    
}
