/**
*  HexColor
*  Copyright (c) Wilhelm Oks 2020
*  Licensed under the MIT license (see LICENSE file)
*/

#if os(macOS)
import AppKit
#else
import UIKit
#endif

public struct HexColor {
    private init() {}
    
    private static let invalidHexCharactersSet = CharacterSet(charactersIn: "0x0123456789abcdefABCDEF").inverted
    
    public static func intFromHexString(_ hex: String) -> UInt32? {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard !s.isEmpty else {
            return nil
        }
        
        if s.hasPrefix("#") {
            s = String(s.dropFirst())
        }
        
        guard s.rangeOfCharacter(from: invalidHexCharactersSet) == nil else {
            return nil
        }
        
        if s.count == 3 { // shorthand 3 digit notation
            s = s + "f" // add alpha
        }
        
        if s.count == 4 { // shorthand 3 digit notation + 1 alpha digit
            s = s.reduce("") { $0 + String($1) + String($1) } //duplicate all digits
        }
        
        if s.count == 6 { // normal notation without alpha
            s = s + "ff" // add alpha
        }
        
        guard s.count == 8 else {
            return nil
        }
        
        let scanner = Scanner(string: s)
                
        var rgb: UInt32 = 0
        scanner.scanHexInt32(&rgb)
        return rgb
    }
    
    public static func rgbaFromInt(_ integer: UInt32) -> (r: CGFloat, g: CGFloat, b: CGFloat, a: CGFloat) {
        let maxValue = CGFloat(255)
        return (
            r: CGFloat((integer & 0xFF000000) >> 24) / maxValue,
            g: CGFloat((integer &   0xFF0000) >> 16) / maxValue,
            b: CGFloat((integer &     0xFF00) >>  8) / maxValue,
            a: CGFloat((integer &       0xFF)      ) / maxValue)
    }
}
