//
//  BladesViewController.swift
//  WBBladesCrashApp
//
//  Created by 竹林七闲 on 2022/4/11.
//

import Foundation
import Cocoa
import WBAppSize

class BladesViewController: NSWindowController {

    lazy var viewController: BladesDispatchViewController = {
        ASTest.test()
        let viewController = BladesDispatchViewController()
        return viewController
    }()

    lazy var bdWindow: NSWindow? = {
        let frame: CGRect = CGRect(x: 0, y: 0, width: 800, height: 650)
        let style: NSWindow.StyleMask = [.titled,.closable,.resizable]
        let back: NSWindow.BackingStoreType = .buffered
        let window: NSWindow = NSWindow(contentRect: frame, styleMask: style, backing: back, defer: false)
        window.title = "WBBlades"
        window.windowController = self
        return window
    }()


    override func windowDidLoad() {
        self.contentViewController = self.viewController
//        self.window?.frame = CGRect(x: 0, y: 0, width: 800, height: 600)
        self.window?.title = "WBBlades"
    }
    
    required init?(coder: NSCoder) {
         super.init(coder: coder)
    }
}
