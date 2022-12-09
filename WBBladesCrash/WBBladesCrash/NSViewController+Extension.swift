//
//  NSViewController+GoBack.swift
//  WBBladesCrashApp
//
//  Created by 竹林七闲 on 2022/4/11.
//

import Foundation
import Cocoa

public extension NSViewController {
    func goBack() {
        let vcWindow = NSStoryboard.main?.instantiateController(withIdentifier: "WindowController") as? NSWindowController
        vcWindow?.window?.center()
        vcWindow?.window?.orderFront(nil)
        vcWindow?.showWindow(nil)
        vcWindow?.window?.setFrameOrigin(self.view.window!.frame.origin)
        let lastWindow = self.view.window
        lastWindow?.close()
    }

    func setBackgroudColor(color: CGColor) {
        let backgroundTag = 10011
        if let backgroundView = self.view.viewWithTag(backgroundTag) {
            backgroundView.layer?.backgroundColor = color
        }

        let backGroundView: NSView = NSView(frame: self.view.bounds)
        backGroundView.autoresizingMask = [.width, .height]
        self.view.addSubview(backGroundView, positioned: .below, relativeTo: self.view)
        backGroundView.wantsLayer = true
        backGroundView.layer?.backgroundColor = color
    }
}

public extension NSTextView {
    func showTextViewBoarder() {
        self.wantsLayer = true
        self.layer?.borderColor = .init(red: CGFloat(234)/CGFloat(255), green: CGFloat(234)/CGFloat(255), blue: CGFloat(234)/CGFloat(255), alpha: 1.0)
        self.layer?.borderWidth = 2
    }
}

public extension NSTextField {
    func showTextFieldBoarder() {
        self.isBordered = true
    }
}

