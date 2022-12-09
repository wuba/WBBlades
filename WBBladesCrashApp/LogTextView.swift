//
//  LogTextView.swift
//  WBBladesCrashProject
//
//  Created by wbblades on 2021/5/14.
//

import Cocoa

class LogTextView: NSTextView{
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
//        fatalError("init(coder:) has not been implemented")
    }
    
    open override func draggingEnded(_ sender: NSDraggingInfo) {
        let bounds = self.visibleRect.size
        let visibleFrame = NSMakeRect(20.0, 67.0, bounds.width, bounds.height)
        if !visibleFrame.contains(sender.draggingLocation) {
            return
        }
        let pasteboard = sender.draggingPasteboard;
        let list = pasteboard.pasteboardItems
        let item = list?[0].string(forType: .fileURL) ?? ""
        
        guard let url = URL.init(string: item) else{
            return
        }
        print(url)
        
        guard let fileData: Data = try? Data.init(contentsOf: url) else{
            return
        }
        let fileString = String.init(data: fileData, encoding: .utf8) ?? ""
        self.string = fileString
        
        NotificationCenter.default.post(name: .init(LogTextViewContentChanged), object: url)
    }
}
