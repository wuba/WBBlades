//
//  Font.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 17/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public struct DefaultBookFont: Equatable {
    public let name: String
    public let size: Int

    public init(name: String, size: Int)
    {
        self.name = name
        self.size = size
    }

    public static func ==(lhs: DefaultBookFont, rhs: DefaultBookFont) -> Bool
    {
        return lhs.name == rhs.name && lhs.size == rhs.size
    }
}

public enum FontColor {
    case Black            
    case White            
    case Red              
    case BrightGreen      
    case Blue             
    case Yellow           
    case Pink             
    case Turquoise        
    case Darkred          
    case Green            
    case Darkblue         
    case Darkyellow	      
    case Violet		      
    case Teal             
    case Gray25		      
    case Gray50	          
    case Periwinkle_CF	  
    case Plum_CF		  
    case Ivory_CF		  
    case Lightturquoise_CF
    case Darkpurple_CF	  
    case Coral_CF		  
    case Oceanblue_CF	  
    case Iceblue_CF	      
    case Darkblue_Cl	  
    case Pink_Cl		  
    case Yellow_Cl		  
    case Turquoise_Cl	  
    case Violet_Cl		  
    case Darkred_Cl	      
    case Teal_Cl		  
    case Blue_Cl		  
    case Skyblue          
    case Lightturquoise   
    case Lightgreen       
    case Lightyellow      
    case Paleblue         
    case Rose             
    case Lavender	      
    case Tan              
    case Lightblue	      
    case Aqua             
    case Lime             
    case Gold		      
    case Lightorange      
    case Orange	          
    case Bluegray	      
    case Gray40	          
    case Darkteal	      
    case Seagreen	      
    case Darkgreen	      
    case Olivegreen       
    case Brown		      
    case Plum		      
    case Indigo	          
    case Gray80	          
    // Default colors
    case DefaultForeground
    case DefaultBackground
}

public enum FontBaseline {
    case Normal
    case Superscript
    case Subscript
}


public enum FontUnderlineStyle {
    case None
    case Single
    case Double
    case SingleAcc
    case DoubleAcc
}

public class Font {
    let handle: FontHandle

    init(withHandle aHandle: FontHandle) {
        handle = aHandle
    }

    /// A name of this font
    public var name: String {
        get {
            return String(cString: xlFontNameA(handle))
        }
        set {
            newValue.utf8CString.withUnsafeBufferPointer {
                xlFontSetNameA(handle, $0.baseAddress)
            }
        }
    }

    /// A size of the font (in points)
    public var size: Int {
        get {
            return Int(xlFontSizeA(handle))
        }
        set {
            xlFontSetSizeA(handle, Int32(newValue))
        }
    }

    /// Should this font use its bold variant or not
    public var bold: Bool {
        get {
            return xlFontBoldA(handle) == 1
        }
        set {
            xlFontSetBoldA(handle, newValue ? 1 : 0)
        }
    }

    /// Should this font use its italic variant or not
    public var italic: Bool {
        get {
            return xlFontItalicA(handle) == 1
        }
        set {
            xlFontSetItalicA(handle, newValue ? 1 : 0)
        }
    }

    /// Should this font use its striked out variant or not
    public var strikeOut: Bool {
        get {
            return xlFontStrikeOutA(handle) == 1
        }
        set {
            xlFontSetStrikeOutA(handle, newValue ? 1 : 0)
        }
    }

    /// Should this font be underlined or not
    public var underline: FontUnderlineStyle {
        get {
            return FontUnderlineStyle.from(raw: xlFontUnderlineA(handle))
        }
        set {
            xlFontSetUnderlineA(handle, newValue.toRaw())
        }
    }

    /// A color of this font
    public var color: FontColor {
        get {
            return FontColor.from(raw: xlFontColorA(handle))
        }
        set {
            xlFontSetColorA(handle, newValue.toRaw())
        }
    }

    /// A baseline for this font
    public var baseline: FontBaseline {
        get {
            return FontBaseline.from(raw: xlFontScriptA(handle))
        }
        set {
            xlFontSetScriptA(handle, newValue.toRaw())
        }
    }
}


fileprivate extension FontBaseline {
    fileprivate static func from(raw: Int32) -> FontBaseline
    {
        switch raw {
        case Int32(SCRIPT_NORMAL.rawValue): return .Normal
        case Int32(SCRIPT_SUPER.rawValue): return .Superscript
        case Int32(SCRIPT_SUB.rawValue): return .Subscript
        default:
            return .Normal
        }
    }

    fileprivate func toRaw() -> Int32
    {
        switch self {
        case .Normal: return  Int32(SCRIPT_NORMAL.rawValue)
        case .Superscript: return Int32(SCRIPT_SUPER.rawValue)
        case .Subscript: return Int32(SCRIPT_SUB.rawValue)
        }
    }
}

internal extension FontUnderlineStyle {
    fileprivate static func from(raw: Int32) -> FontUnderlineStyle
    {
        switch raw {
        case Int32(UNDERLINE_NONE.rawValue): return .None
        case Int32(UNDERLINE_SINGLE.rawValue): return .Single
        case Int32(UNDERLINE_DOUBLE.rawValue): return .Double
        case Int32(UNDERLINE_SINGLEACC.rawValue): return .SingleAcc
        case Int32(UNDERLINE_DOUBLEACC.rawValue): return .DoubleAcc
        default:
            return .None
        }
    }

    fileprivate func toRaw() -> Int32
    {
        switch self {
        case .None: return  Int32(UNDERLINE_NONE.rawValue)
        case .Single: return Int32(UNDERLINE_SINGLE.rawValue)
        case .Double: return Int32(UNDERLINE_DOUBLE.rawValue)
        case .SingleAcc: return Int32(UNDERLINE_SINGLEACC.rawValue)
        case .DoubleAcc: return Int32(UNDERLINE_DOUBLEACC.rawValue)
        }
    }
}

internal extension FontColor {
    internal static func from(raw: Int32) -> FontColor
    {
        switch raw {
        case Int32(COLOR_BLACK.rawValue): return .Black
        case Int32(COLOR_WHITE.rawValue): return .White
        case Int32(COLOR_RED.rawValue): return .Red
        case Int32(COLOR_BRIGHTGREEN.rawValue): return .BrightGreen
        case Int32(COLOR_BLUE.rawValue): return .Blue
        case Int32(COLOR_YELLOW.rawValue): return .Yellow
        case Int32(COLOR_PINK.rawValue): return .Pink
        case Int32(COLOR_TURQUOISE.rawValue): return .Turquoise
        case Int32(COLOR_DARKRED.rawValue): return .Darkred
        case Int32(COLOR_GREEN.rawValue): return .Green
        case Int32(COLOR_DARKBLUE.rawValue): return .Darkblue
        case Int32(COLOR_DARKYELLOW.rawValue): return .Darkyellow
        case Int32(COLOR_VIOLET.rawValue): return .Violet
        case Int32(COLOR_TEAL.rawValue): return .Teal
        case Int32(COLOR_GRAY25.rawValue): return .Gray25
        case Int32(COLOR_GRAY50.rawValue): return .Gray50
        case Int32(COLOR_PERIWINKLE_CF.rawValue): return .Periwinkle_CF
        case Int32(COLOR_PLUM_CF.rawValue): return .Plum_CF
        case Int32(COLOR_IVORY_CF.rawValue): return .Ivory_CF
        case Int32(COLOR_LIGHTTURQUOISE_CF.rawValue): return .Lightturquoise_CF
        case Int32(COLOR_DARKPURPLE_CF.rawValue): return .Darkpurple_CF
        case Int32(COLOR_CORAL_CF.rawValue): return .Coral_CF
        case Int32(COLOR_OCEANBLUE_CF.rawValue): return .Oceanblue_CF
        case Int32(COLOR_ICEBLUE_CF.rawValue): return .Iceblue_CF
        case Int32(COLOR_DARKBLUE_CL.rawValue): return .Darkblue_Cl
        case Int32(COLOR_PINK_CL.rawValue): return .Pink_Cl
        case Int32(COLOR_YELLOW_CL.rawValue): return .Yellow_Cl
        case Int32(COLOR_TURQUOISE_CL.rawValue): return .Turquoise_Cl
        case Int32(COLOR_VIOLET_CL.rawValue): return .Violet_Cl
        case Int32(COLOR_DARKRED_CL.rawValue): return .Darkred_Cl
        case Int32(COLOR_TEAL_CL.rawValue): return .Teal_Cl
        case Int32(COLOR_BLUE_CL.rawValue): return .Blue_Cl
        case Int32(COLOR_SKYBLUE.rawValue): return .Skyblue
        case Int32(COLOR_LIGHTTURQUOISE.rawValue): return .Lightturquoise
        case Int32(COLOR_LIGHTGREEN.rawValue): return .Lightgreen
        case Int32(COLOR_LIGHTYELLOW.rawValue): return .Lightyellow
        case Int32(COLOR_PALEBLUE.rawValue): return .Paleblue
        case Int32(COLOR_ROSE.rawValue): return .Rose
        case Int32(COLOR_LAVENDER.rawValue): return .Lavender
        case Int32(COLOR_TAN.rawValue): return .Tan
        case Int32(COLOR_LIGHTBLUE.rawValue): return .Lightblue
        case Int32(COLOR_AQUA.rawValue): return .Aqua
        case Int32(COLOR_LIME.rawValue): return .Lime
        case Int32(COLOR_GOLD.rawValue): return .Gold
        case Int32(COLOR_LIGHTORANGE.rawValue): return .Lightorange
        case Int32(COLOR_ORANGE.rawValue): return .Orange
        case Int32(COLOR_BLUEGRAY.rawValue): return .Bluegray
        case Int32(COLOR_GRAY40.rawValue): return .Gray40
        case Int32(COLOR_DARKTEAL.rawValue): return .Darkteal
        case Int32(COLOR_SEAGREEN.rawValue): return .Seagreen
        case Int32(COLOR_DARKGREEN.rawValue): return .Darkgreen
        case Int32(COLOR_OLIVEGREEN.rawValue): return .Olivegreen
        case Int32(COLOR_BROWN.rawValue): return .Brown
        case Int32(COLOR_PLUM.rawValue): return .Plum
        case Int32(COLOR_INDIGO.rawValue): return .Indigo
        case Int32(COLOR_GRAY80.rawValue): return .Gray80
        case Int32(COLOR_DEFAULT_FOREGROUND.rawValue): return .DefaultForeground
        case Int32(COLOR_DEFAULT_BACKGROUND.rawValue): return .DefaultBackground
        default: return .DefaultForeground
        }
    }

    internal func toRaw() -> Int32
    {
        switch self {
        case .Black: return Int32(COLOR_BLACK.rawValue)
        case .White: return Int32(COLOR_WHITE.rawValue)
        case .Red: return Int32(COLOR_RED.rawValue)
        case .BrightGreen: return Int32(COLOR_BRIGHTGREEN.rawValue)
        case .Blue: return Int32(COLOR_BLUE.rawValue)
        case .Yellow: return Int32(COLOR_YELLOW.rawValue)
        case .Pink: return Int32(COLOR_PINK.rawValue)
        case .Turquoise: return Int32(COLOR_TURQUOISE.rawValue)
        case .Darkred: return Int32(COLOR_DARKRED.rawValue)
        case .Green: return Int32(COLOR_GREEN.rawValue)
        case .Darkblue: return Int32(COLOR_DARKBLUE.rawValue)
        case .Darkyellow: return Int32(COLOR_DARKYELLOW.rawValue)
        case .Violet: return Int32(COLOR_VIOLET.rawValue)
        case .Teal: return Int32(COLOR_TEAL.rawValue)
        case .Gray25: return Int32(COLOR_GRAY25.rawValue)
        case .Gray50: return Int32(COLOR_GRAY50.rawValue)
        case .Periwinkle_CF: return Int32(COLOR_PERIWINKLE_CF.rawValue)
        case .Plum_CF: return Int32(COLOR_PLUM_CF.rawValue)
        case .Ivory_CF: return Int32(COLOR_IVORY_CF.rawValue)
        case .Lightturquoise_CF: return Int32(COLOR_LIGHTTURQUOISE_CF.rawValue)
        case .Darkpurple_CF: return Int32(COLOR_DARKPURPLE_CF.rawValue)
        case .Coral_CF: return Int32(COLOR_CORAL_CF.rawValue)
        case .Oceanblue_CF: return Int32(COLOR_OCEANBLUE_CF.rawValue)
        case .Iceblue_CF: return Int32(COLOR_ICEBLUE_CF.rawValue)
        case .Darkblue_Cl: return Int32(COLOR_DARKBLUE_CL.rawValue)
        case .Pink_Cl: return Int32(COLOR_PINK_CL.rawValue)
        case .Yellow_Cl: return Int32(COLOR_YELLOW_CL.rawValue)
        case .Turquoise_Cl: return Int32(COLOR_TURQUOISE_CL.rawValue)
        case .Violet_Cl: return Int32(COLOR_VIOLET_CL.rawValue)
        case .Darkred_Cl: return Int32(COLOR_DARKRED_CL.rawValue)
        case .Teal_Cl: return Int32(COLOR_TEAL_CL.rawValue)
        case .Blue_Cl: return Int32(COLOR_BLUE_CL.rawValue)
        case .Skyblue: return Int32(COLOR_SKYBLUE.rawValue)
        case .Lightturquoise: return Int32(COLOR_LIGHTTURQUOISE.rawValue)
        case .Lightgreen: return Int32(COLOR_LIGHTGREEN.rawValue)
        case .Lightyellow: return Int32(COLOR_LIGHTYELLOW.rawValue)
        case .Paleblue: return Int32(COLOR_PALEBLUE.rawValue)
        case .Rose: return Int32(COLOR_ROSE.rawValue)
        case .Lavender: return Int32(COLOR_LAVENDER.rawValue)
        case .Tan: return Int32(COLOR_TAN.rawValue)
        case .Lightblue: return Int32(COLOR_LIGHTBLUE.rawValue)
        case .Aqua: return Int32(COLOR_AQUA.rawValue)
        case .Lime: return Int32(COLOR_LIME.rawValue)
        case .Gold: return Int32(COLOR_GOLD.rawValue)
        case .Lightorange: return Int32(COLOR_LIGHTORANGE.rawValue)
        case .Orange: return Int32(COLOR_ORANGE.rawValue)
        case .Bluegray: return Int32(COLOR_BLUEGRAY.rawValue)
        case .Gray40: return Int32(COLOR_GRAY40.rawValue)
        case .Darkteal: return Int32(COLOR_DARKTEAL.rawValue)
        case .Seagreen: return Int32(COLOR_SEAGREEN.rawValue)
        case .Darkgreen: return Int32(COLOR_DARKGREEN.rawValue)
        case .Olivegreen: return Int32(COLOR_OLIVEGREEN.rawValue)
        case .Brown: return Int32(COLOR_BROWN.rawValue)
        case .Plum: return Int32(COLOR_PLUM.rawValue)
        case .Indigo: return Int32(COLOR_INDIGO.rawValue)
        case .Gray80: return Int32(COLOR_GRAY80.rawValue)
        case .DefaultForeground: return Int32(COLOR_DEFAULT_FOREGROUND.rawValue)
        case .DefaultBackground: return Int32(COLOR_DEFAULT_BACKGROUND.rawValue)
        }
    }
}
