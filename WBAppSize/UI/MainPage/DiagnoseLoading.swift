//
//  DiagnoseLoading.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/4/1.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class DiagnoseLoading: NSView ,NibLoadable{

    @IBOutlet weak var progressBar: NSProgressIndicator!
    @IBOutlet weak var hintTextView: NSTextField!
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        self.layer?.backgroundColor = NSColor.init(srgbRed: 0/255.0, green: 0/255.0, blue: 0/255.0, alpha: 0.8).cgColor

        // Drawing code here.
    }
    
    func startLoading() {
        progressBar.startAnimation(nil)
    }
    
    func stopLoading() {
        progressBar.stopAnimation(nil)
    }
    
    func showHintInfo(hint:String) -> Void {
        hintTextView.stringValue = hint
    }
}
