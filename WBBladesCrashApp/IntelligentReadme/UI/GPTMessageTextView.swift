//
//  GPTMessageTextView.swift
//  WBBladesCrashApp
//
//  Created by 58 on 2023/7/26.
//

import Cocoa

class GPTMessageTextView: NSTextView {
    
    var minHeight: CGFloat = 60
    var maxHeight: CGFloat = 300
    var contentHeightChange: ((CGFloat) -> Void)?
    var placeholder: String = ""
    
    override func becomeFirstResponder() -> Bool {
        needsDisplay = true
        return super.becomeFirstResponder()
    }
    
    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        if string.isEmpty {
            let placeholderAttr = NSAttributedString(string: placeholder,
                                                     attributes: [.foregroundColor : NSColor.gray, .font: font ?? NSFont.systemFont(ofSize: 13)])
            placeholderAttr.draw(at: CGPoint(x: 5, y: 0))
        }
    }
    
    override func didChangeText() {
        super.didChangeText()
        contentHeightChange?(calcuContainerHeight)
    }
    
    private var calcuContainerHeight: CGFloat {
        guard let textContainer = textContainer,
                let layoutManager = textContainer.layoutManager else {
            return minHeight
        }
        let usedRect = layoutManager.usedRect(for: textContainer)
        var height = usedRect.size.height
        if height < self.minHeight {
            height = self.minHeight
        } else if height > self.maxHeight {
            height = self.maxHeight
        }
        return height
    }
}
