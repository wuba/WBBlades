/**
*  HexColor
*  Copyright (c) Wilhelm Oks 2020
*  Licensed under the MIT license (see LICENSE file)
*/

#if os(macOS)

import AppKit
public extension NSColor {
    static func fromHexString(_ hex: String, alpha: CGFloat? = nil) -> NSColor? {
        guard let integer = HexColor.intFromHexString(hex) else { return nil }
        let components = HexColor.rgbaFromInt(integer)
        
        if let alpha = alpha {
            return NSColor(
                red:   components.r,
                green: components.g,
                blue:  components.b,
                alpha: alpha)
        } else {
            return NSColor(
                red:   components.r,
                green: components.g,
                blue:  components.b,
                alpha: components.a)
        }
    }
}

#endif
