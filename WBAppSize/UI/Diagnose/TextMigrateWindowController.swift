//
//  TextMigrateWindowController.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/4/1.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class TextMigrateWindowController: NSWindowController {

    override func windowDidLoad() {
        super.windowDidLoad()
    
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    lazy var myWindow: NSWindow? = {
        let frame: CGRect = CGRect(x: 0, y: 0, width: 800, height: 600)
        let style: NSWindow.StyleMask = [.titled,.closable,.resizable]
        let back: NSWindow.BackingStoreType = .buffered
        let window: NSWindow = NSWindow(contentRect: frame, styleMask: style, backing: back, defer: false)
        window.title = "__TEXT段迁移配置"
        window.windowController = self
        // 不允许拉伸window宽高
        window.styleMask.remove(.resizable)
        return window
}()
    
    lazy var viewController: TextMigrateViewController = {
        let viewController = TextMigrateViewController()
        return viewController
    }()
    
    override init(window: NSWindow?) {
        super.init(window: window)
        self.window = self.myWindow
        self.contentViewController = self.viewController
        self.window?.center()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

}
