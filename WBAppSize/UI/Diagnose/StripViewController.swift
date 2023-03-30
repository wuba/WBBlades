//
//  StripViewController.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/4/11.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class StripViewController: NSViewController {

    var frameworksDir:String?

    @IBOutlet var descText: NSTextField!
    @IBOutlet var checkBtn: NSButton!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.descText.stringValue = ASTextDictionary.valueForKey(key: "stripDescContent");
        self.checkBtn.title = ASTextDictionary.valueForKey(key: "stripCheckBtnTitle");
        self.title = ASTextDictionary.valueForKey(key: "stripCheckBtnTitle");
        
        // Do view setup here.
    }
    
    @IBAction func checkFrameworks(_ sender: Any) {
        NSWorkspace.shared.selectFile(self.frameworksDir, inFileViewerRootedAtPath:"")
    }
}
