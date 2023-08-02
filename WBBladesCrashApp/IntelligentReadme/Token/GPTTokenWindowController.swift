//
//  GPTTokenWindowController.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Cocoa

class GPTTokenWindowManager {
    static let share: GPTTokenWindowManager = GPTTokenWindowManager()
    private weak var gptTokenWindow: NSWindow?
    func show() {
        if let window = gptTokenWindow {
            window.orderFrontRegardless()
        } else {
            let tmwind = GPTTokenWindowController()
            tmwind.showWindow(self)
            gptTokenWindow = tmwind.window
        }
    }
    
    func close() {
        if let window = gptTokenWindow {
            window.close()
        }
    }
}

class GPTTokenWindowController: NSWindowController {

    override func windowDidLoad() {
        super.windowDidLoad()
    
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    lazy var myWindow: NSWindow? = {
        let frame: CGRect = CGRect(x: 0, y: 0, width: 800, height: 600)
        let style: NSWindow.StyleMask = [.titled,.closable,.resizable]
        let back: NSWindow.BackingStoreType = .buffered
        let window: NSWindow = NSWindow(contentRect: frame, styleMask: style, backing: back, defer: false)
        window.title = "设置API_KEY"
        window.windowController = self
        // 不允许拉伸window宽高
        window.styleMask.remove(.resizable)
        return window
}()
    
    lazy var viewController: GPTTokenViewController = {
        let viewController = GPTTokenViewController()
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
