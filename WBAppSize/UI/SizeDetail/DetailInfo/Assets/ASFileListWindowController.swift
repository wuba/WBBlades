//
//  ASFileListWindowController.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/8.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASFileListWindowController: NSWindowController {
    var allFiles: [ASShowFileListBaseModel] = []

    var _mainBundle : ASMainBundle?
    var mainBundle : ASMainBundle?
    {
        get {
            return self._mainBundle
        }
        set(newBundle) {
            self._mainBundle = newBundle
            guard let bundle = newBundle else {
                return
            }
            self.allFiles = ASFileModel.readFilesFrom(mainBundle: bundle)
            self.listViewController.files = self.allFiles
            self.listViewController.updateFlatFiles()
        }
    }
    
        
    override func windowDidLoad() {
        super.windowDidLoad()
//        self.contentViewController = self.listViewController
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    lazy var myWindow: NSWindow? = {
        let frame: CGRect = CGRect(x: 0, y: 0, width: 800, height: 600)
        let style: NSWindow.StyleMask = [.titled,.closable,.resizable]
        let back: NSWindow.BackingStoreType = .buffered
        let window: NSWindow = NSWindow(contentRect: frame, styleMask: style, backing: back, defer: false)
        window.title = "Asset"
        window.windowController = self
        return window
    }()
    
    lazy var listViewController: ASFileListViewController = {
        let viewController = ASFileListViewController()
        viewController.files = self.allFiles
        return viewController
    }()
    
    override init(window: NSWindow?) {
        super.init(window: window)
        self.window = self.myWindow
        self.window?.center()
        self.contentViewController = self.listViewController
    }

    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

}
