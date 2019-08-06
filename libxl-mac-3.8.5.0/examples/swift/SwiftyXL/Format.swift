//
//  Format.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 17/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public enum FormatHorizontalAlignment {
    case General
    case Left
    case Center
    case Right
    case Fill
    case Justify
    case Merge
    case Distributed
}

public enum FormatVerticalAlignment {
    case Top
    case Center
    case Bottom
    case Justify
    case Distributed
}

public enum FormatTextRotation: Equatable {
    case Clockwise(degrees: Int)
    case Counterclockwise(degrees: Int)
    case Vertical
}

public typealias FormatBorderColor = FontColor

public enum FormatBorderStyle {
    case None
    case Thin
    case Medium
    case Dashed
    case Dotted
    case Thick
    case Double
    case Hair
    case MediumDashed
    case DashDot
    case MediumDashDot
    case DashDotDot
    case MediumDashDotDot
    case SlantDashDot
}

public enum FormatDiagonalBorderType: Equatable {
    case None
    case Up  (style: FormatBorderStyle, color: FormatBorderColor)
    case Down(style: FormatBorderStyle, color: FormatBorderColor)
    case Both(style: FormatBorderStyle, color: FormatBorderColor)
}

public enum FormatBorderPosition {
    case LeftBorder
    case RightBorder
    case TopBorder
    case BottomBorder
}

public enum NumberFormat: Equatable {
    case General
    case Text
    case Number(decimalPoint: Bool, thousandsSeparator: Bool)
    case NumberWithNegativesInBrackets(decimalPoint: Bool, negativesAreRed: Bool)
    case Currency(decimalPoint: Bool, negativesAreRed: Bool)
    case Percent(decimalPoint: Bool)
    case Scientific
    case ScientificAlternative
    case Fraction(withOneDigit: Bool)
    case Account(decimalPoint: Bool, currencySymbol: Bool)
    case Date
    case CustomDate(format: CustomDateFormat)

    public enum CustomDateFormat {
        // Date
        case DayMonth
        case DayMonthYear
        case MonthYear
        // Time
        case HoursMinutes         // 24-hour time
        case HoursMinutesSeconds
        case HoursMinutesAM       // 12-hour time
        case HoursMinutesSecondsAM
        case MinutesSeconds
        case PrefixedHoursMinutesSeconds
        case MinutesSecondsWithSuffix
        // Full
        case MonthDayYearHoursMinutes
    }
}

public typealias FormatFillColor = FormatBorderColor

public enum FormatFillPattern: Equatable {
    case None
    case Solid (foreground: FormatFillColor)
    case Gray25 (foreground: FormatFillColor, background: FormatFillColor)
    case Gray50 (foreground: FormatFillColor, background: FormatFillColor)
    case Gray75 (foreground: FormatFillColor, background: FormatFillColor)
    case HorizontalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case ThinHorizontalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case VerticalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case ThinVerticalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case DiagonalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case ThinDiagonalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case ReverseDiagonalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case ThinReverseDiagonalStripes (foreground: FormatFillColor, background: FormatFillColor)
    case DiagonalCrosshatch (foreground: FormatFillColor, background: FormatFillColor)
    case ThinDiagonalCrosshatch (foreground: FormatFillColor, background: FormatFillColor)
    case ThickDiagonalCrosshatch (foreground: FormatFillColor, background: FormatFillColor)
    case ThinHorizontalCrosshatch (foreground: FormatFillColor, background: FormatFillColor)
    case Gray12P5 (foreground: FormatFillColor, background: FormatFillColor)
    case Gray6P25 (foreground: FormatFillColor, background: FormatFillColor)
}

public class Format {
    let handle: FormatHandle

    init(withHandle aHandle: FormatHandle) {
        handle = aHandle
    }

    /// Is this format locked from user edits
    public var locked: Bool {
        get {
            return xlFormatLockedA(handle) == 1
        }
        set {
            xlFormatSetLockedA(handle, newValue ? 1 : 0)
        }
    }
    /// Is this format hidden from user
    public var hidden: Bool {
        get {
            return xlFormatHiddenA(handle) == 1
        }
        set {
            xlFormatSetHiddenA(handle, newValue ? 1 : 0)
        }
    }

    /// A font used in this format
    public var font: Font? {
        get {
            return (xlFormatFontA(handle) as FontHandle?).map { Font(withHandle: $0)}
        }
        set {
            if let newFont = newValue {
                xlFormatSetFontA(handle, newFont.handle)
            }
        }
    }

    /// A number format
    public var numberFormat: NumberFormat {
        get {
            return NumberFormat.from(raw: xlFormatNumFormatA(handle))
        }
        set {
            xlFormatSetNumFormatA(handle, newValue.toRaw())
        }
    }

    /// A horizontal alignment mode used in this format
    public var horizontalAlignment: FormatHorizontalAlignment {
        get {
            return FormatHorizontalAlignment.from(raw: xlFormatAlignHA(handle))
        }
        set {
            xlFormatSetAlignHA(handle, newValue.toRaw())
        }
    }

    /// A vertical alignment mode used in this format
    public var verticalAlignment: FormatVerticalAlignment {
        get {
            return FormatVerticalAlignment.from(raw: xlFormatAlignVA(handle))
        }
        set {
            xlFormatSetAlignVA(handle, newValue.toRaw())
        }
    }

    /// To wrap a cell text or not to wrap
    public var wrapCellText: Bool {
        get {
            return xlFormatWrapA(handle) == 1
        }
        set {
            xlFormatSetWrapA(handle, newValue ? 1 : 0)
        }
    }

    /// Text rotation value
    public var textRotation: FormatTextRotation {
        get {
            return FormatTextRotation.from(raw: xlFormatRotationA(handle))
        }
        set {
            xlFormatSetRotationA(handle, newValue.toRaw())
        }
    }

    public static let maxTextIndentationLevel = 15

    /// A text indentation level
    public var textIndentationLevel: Int {
        get {
            return Int(xlFormatIndentA(handle))
        }
        set {
            xlFormatSetIndentA(handle, Int32(min(Format.maxTextIndentationLevel, newValue)))
        }
    }

    /// Shrink cells to fit their content
    public var shrinkToFit: Bool {
        get {
            return xlFormatShrinkToFitA(handle) == 1
        }
        set {
            xlFormatSetShrinkToFitA(handle, newValue ? 1 : 0)
        }
    }

    /// Returns a border style used by default in this format
    public func set(defaultBorderStyle style: FormatBorderStyle)
    {
        xlFormatSetBorderA(handle, style.toRaw())
    }

    /// Returns a style for the specified border
    public func style(of target: FormatBorderPosition) -> FormatBorderStyle
    {
        switch target {
        case .LeftBorder:
            return FormatBorderStyle.from(raw: xlFormatBorderLeftA(handle))
        case .RightBorder:
            return FormatBorderStyle.from(raw: xlFormatBorderRightA(handle))
        case .TopBorder:
            return FormatBorderStyle.from(raw: xlFormatBorderTopA(handle))
        case .BottomBorder:
            return FormatBorderStyle.from(raw: xlFormatBorderBottomA(handle))
        }
    }

    /// Sets a style for the specified border
    public func set(style: FormatBorderStyle, for target: FormatBorderPosition)
    {
        switch target {
        case .LeftBorder:
            xlFormatSetBorderLeftA(handle, style.toRaw())
        case .RightBorder:
            xlFormatSetBorderRightA(handle, style.toRaw())
        case .TopBorder:
            xlFormatSetBorderTopA(handle, style.toRaw())
        case .BottomBorder:
            xlFormatSetBorderBottomA(handle, style.toRaw())
        }
    }

    /// Sets a default border color for this format
    public func set(defaultBorderColor color: FormatBorderColor)
    {
        xlFormatSetBorderColorA(handle, color.toRaw())
    }

    /// Returns a color of the specified border
    public func color(of target: FormatBorderPosition) -> FormatBorderColor
    {
        switch target {
        case .LeftBorder:
            return FormatBorderColor.from(raw: xlFormatBorderLeftColorA(handle))
        case .RightBorder:
            return FormatBorderColor.from(raw: xlFormatBorderRightColorA(handle))
        case .TopBorder:
            return FormatBorderColor.from(raw: xlFormatBorderTopColorA(handle))
        case .BottomBorder:
            return FormatBorderColor.from(raw: xlFormatBorderBottomColorA(handle))
        }
    }

    /// Sets a color for the specified border
    public func set(color: FormatBorderColor, for target: FormatBorderPosition)
    {
        switch target {
        case .LeftBorder:
            xlFormatSetBorderLeftColorA(handle, color.toRaw())
        case .RightBorder:
            xlFormatSetBorderRightColorA(handle, color.toRaw())
        case .TopBorder:
            xlFormatSetBorderTopColorA(handle, color.toRaw())
        case .BottomBorder:
            xlFormatSetBorderBottomColorA(handle, color.toRaw())
        }
    }

    // A diagonal border style used in this format
    public var diagonalBorder: FormatDiagonalBorderType {
        get {
            let rawType = xlFormatBorderDiagonalA(handle)
            let style = FormatBorderStyle.from(raw: xlFormatBorderDiagonalStyleA(handle))
            let color = FormatBorderColor.from(raw: xlFormatBorderDiagonalColorA(handle))
            return FormatDiagonalBorderType.from(rawType: rawType, style: style, color: color)
        }
        set {
            switch newValue {
            case .None:
                xlFormatSetBorderDiagonalA(handle, newValue.toRawType())
            case .Up(let s, let c), .Down(let s, let c), .Both(let s, let c):
                xlFormatSetBorderDiagonalA(handle, newValue.toRawType())
                xlFormatSetBorderDiagonalStyleA(handle, s.toRaw())
                xlFormatSetBorderDiagonalColorA(handle, c.toRaw())
            }
        }
    }

    // A fill pattern to be used in this format
    public var fillPattern: FormatFillPattern {
        get {
            let rawType = xlFormatFillPatternA(handle)
            let foreground = FormatFillColor.from(raw: xlFormatPatternForegroundColorA(handle))
            let background = FormatFillColor.from(raw: xlFormatPatternBackgroundColorA(handle))
            return FormatFillPattern.from(rawType: rawType, foreground: foreground, background: background)
        }
        set {
            switch newValue {
            case .None:
                xlFormatSetFillPatternA(handle, newValue.toRawType())
            case .Solid(let foreground):
                xlFormatSetFillPatternA(handle, newValue.toRawType())
                xlFormatSetPatternForegroundColorA(handle, foreground.toRaw())
            case .ThinHorizontalCrosshatch(let f, let b), .ThickDiagonalCrosshatch(let f, let b), .Gray25(let f, let b), .HorizontalStripes(let f, let b), .DiagonalStripes(let f, let b), .Gray12P5(let f, let b), .ThinDiagonalCrosshatch(let f, let b), .ThinHorizontalStripes(let f, let b), .DiagonalCrosshatch(let f, let b), .Gray50(let f, let b), .VerticalStripes(let f, let b), .Gray75(let f, let b), .ThinDiagonalStripes(let f, let b), .ReverseDiagonalStripes(let f, let b), .ThinVerticalStripes(let f, let b), .ThinReverseDiagonalStripes(let f, let b), .Gray6P25(let f, let b):
                xlFormatSetFillPatternA(handle, newValue.toRawType())
                xlFormatSetPatternForegroundColorA(handle, f.toRaw())
                xlFormatSetPatternBackgroundColorA(handle, b.toRaw())
            }
        }
    }
}

// MARK: - Private Extensions (serialization/deserialization) -


fileprivate extension FormatTextRotation {

    func toRaw() -> Int32
    {
        switch self {
        case .Vertical:
            return 255
        case .Counterclockwise(let degrees):
            return Int32(min(90, degrees))
        case .Clockwise(let degrees):
            return Int32(min(180, degrees + 90))
        }
    }

    static func from(raw: Int32) -> FormatTextRotation
    {
        switch raw {
        case 0...90:
            return .Counterclockwise(degrees: Int(raw))
        case 91...180:
            return .Clockwise(degrees: Int(raw - 90))
        case 255:
            return .Vertical
        default:
            fatalError("Invalid Rotation raw value")
        }
    }
}

fileprivate extension FormatDiagonalBorderType {

    func toRawType() -> Int32
    {
        switch self {
        case .None:
            return Int32(BORDERDIAGONAL_NONE.rawValue)
        case .Down:
            return Int32(BORDERDIAGONAL_DOWN.rawValue)
        case .Up:
            return Int32(BORDERDIAGONAL_UP.rawValue)
        case .Both:
            return Int32(BORDERDIAGONAL_BOTH.rawValue)
        }
    }

    static func from(rawType raw: Int32, style: FormatBorderStyle, color: FormatBorderColor) -> FormatDiagonalBorderType
    {
        switch raw {
        case Int32(BORDERDIAGONAL_NONE.rawValue):
            return .None
        case Int32(BORDERDIAGONAL_DOWN.rawValue):
            return .Down(style: style, color: color)
        case Int32(BORDERDIAGONAL_UP.rawValue):
            return .Up(style: style, color: color)
        case Int32(BORDERDIAGONAL_BOTH.rawValue):
            return .Both(style: style, color: color)
        default:
            fatalError("Invalid Diagonal Border Style raw value")
        }
    }
}

fileprivate extension FormatFillPattern {

    func toRawType() -> Int32
    {
        switch self {
        case .None:
            return Int32(FILLPATTERN_NONE.rawValue)
        case .Solid (_):
            return Int32(FILLPATTERN_SOLID.rawValue)
        case .Gray25(_ ,_):
            return Int32(FILLPATTERN_GRAY25.rawValue)
        case .Gray50(_ ,_):
            return Int32(FILLPATTERN_GRAY50.rawValue)
        case .Gray75(_ ,_):
            return Int32(FILLPATTERN_GRAY75.rawValue)
        case .HorizontalStripes(_ ,_):
            return Int32(FILLPATTERN_HORSTRIPE.rawValue)
        case .ThinHorizontalStripes(_ ,_):
            return Int32(FILLPATTERN_THINHORSTRIPE.rawValue)
        case .VerticalStripes(_ ,_):
            return Int32(FILLPATTERN_VERSTRIPE.rawValue)
        case .ThinVerticalStripes(_ ,_):
            return Int32(FILLPATTERN_THINVERSTRIPE.rawValue)
        case .DiagonalStripes(_ ,_):
            return Int32(FILLPATTERN_DIAGSTRIPE.rawValue)
        case .ThinDiagonalStripes(_ ,_):
            return Int32(FILLPATTERN_THINDIAGSTRIPE.rawValue)
        case .ReverseDiagonalStripes(_ ,_):
            return Int32(FILLPATTERN_REVDIAGSTRIPE.rawValue)
        case .ThinReverseDiagonalStripes(_ ,_):
            return Int32(FILLPATTERN_THINREVDIAGSTRIPE.rawValue)
        case .DiagonalCrosshatch(_ ,_):
            return Int32(FILLPATTERN_DIAGCROSSHATCH.rawValue)
        case .ThinDiagonalCrosshatch(_ ,_):
            return Int32(FILLPATTERN_THINDIAGCROSSHATCH.rawValue)
        case .ThickDiagonalCrosshatch(_ ,_):
            return Int32(FILLPATTERN_THICKDIAGCROSSHATCH.rawValue)
        case .ThinHorizontalCrosshatch(_ ,_):
            return Int32(FILLPATTERN_THINHORCROSSHATCH.rawValue)
        case .Gray12P5(_ ,_):
            return Int32(FILLPATTERN_GRAY12P5.rawValue)
        case .Gray6P25(_ ,_):
            return Int32(FILLPATTERN_GRAY6P25.rawValue)
        }
    }

    static func from(rawType raw: Int32, foreground: FormatFillColor, background: FormatFillColor) -> FormatFillPattern
    {
        switch raw {
        case Int32(FILLPATTERN_NONE.rawValue):
            return .None
        case Int32(FILLPATTERN_SOLID.rawValue):
            return .Solid(foreground: foreground)
        case Int32(FILLPATTERN_THINHORCROSSHATCH.rawValue):
            return .ThinHorizontalCrosshatch(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THICKDIAGCROSSHATCH.rawValue):
            return .ThickDiagonalCrosshatch(foreground: foreground, background:background)
        case Int32(FILLPATTERN_GRAY25.rawValue):
            return .Gray25(foreground: foreground, background:background)
        case Int32(FILLPATTERN_HORSTRIPE.rawValue):
            return .HorizontalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_DIAGSTRIPE.rawValue):
            return .DiagonalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_GRAY12P5.rawValue):
            return .Gray12P5(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THINDIAGCROSSHATCH.rawValue):
            return .ThinDiagonalCrosshatch(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THINHORSTRIPE.rawValue):
            return .ThinHorizontalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_DIAGCROSSHATCH.rawValue):
            return .DiagonalCrosshatch(foreground: foreground, background:background)
        case Int32(FILLPATTERN_GRAY50.rawValue):
            return .Gray50(foreground: foreground, background:background)
        case Int32(FILLPATTERN_VERSTRIPE.rawValue):
            return .VerticalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_GRAY75.rawValue):
            return .Gray75(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THINDIAGSTRIPE.rawValue):
            return .ThinDiagonalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_REVDIAGSTRIPE.rawValue):
            return .ReverseDiagonalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THINVERSTRIPE.rawValue):
            return .ThinVerticalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_THINREVDIAGSTRIPE.rawValue):
            return .ThinReverseDiagonalStripes(foreground: foreground, background:background)
        case Int32(FILLPATTERN_GRAY6P25.rawValue):
            return .Gray6P25(foreground: foreground, background:background)
        default:
            fatalError("Invalid Format Fill Pattern raw value")
        }
    }
}


fileprivate extension FormatHorizontalAlignment {

    func toRaw() -> Int32
    {
        switch self {
        case .General:
            return Int32(ALIGNH_GENERAL.rawValue)
        case .Left:
            return Int32(ALIGNH_LEFT.rawValue)
        case .Center:
            return Int32(ALIGNH_CENTER.rawValue)
        case .Right:
            return Int32(ALIGNH_RIGHT.rawValue)
        case .Fill:
            return Int32(ALIGNH_FILL.rawValue)
        case .Justify:
            return Int32(ALIGNH_JUSTIFY.rawValue)
        case .Merge:
            return Int32(ALIGNH_MERGE.rawValue)
        case .Distributed:
            return Int32(ALIGNH_DISTRIBUTED.rawValue)
        }
    }

    static func from(raw: Int32) -> FormatHorizontalAlignment
    {
        switch raw {
        case Int32(ALIGNH_GENERAL.rawValue):
            return .General
        case Int32(ALIGNH_LEFT.rawValue):
            return .Left
        case Int32(ALIGNH_CENTER.rawValue):
            return .Center
        case Int32(ALIGNH_RIGHT.rawValue):
            return .Right
        case Int32(ALIGNH_FILL.rawValue):
            return .Fill
        case Int32(ALIGNH_JUSTIFY.rawValue):
            return .Justify
        case Int32(ALIGNH_MERGE.rawValue):
            return .Merge
        case Int32(ALIGNH_DISTRIBUTED.rawValue):
            return .Distributed
        default:
            fatalError("Invalid Horizontal Alignment raw value")
        }
    }
}

fileprivate extension FormatBorderStyle {

    func toRaw() -> Int32
    {
        switch self {
        case .None:
            return Int32(BORDERSTYLE_NONE.rawValue)
        case .Thin:
            return Int32(BORDERSTYLE_THIN.rawValue)
        case .Medium:
            return Int32(BORDERSTYLE_MEDIUM.rawValue)
        case .Dashed:
            return Int32(BORDERSTYLE_DASHED.rawValue)
        case .Dotted:
            return Int32(BORDERSTYLE_DOTTED.rawValue)
        case .Thick:
            return Int32(BORDERSTYLE_THICK.rawValue)
        case .Double:
            return Int32(BORDERSTYLE_DOUBLE.rawValue)
        case .Hair:
            return Int32(BORDERSTYLE_HAIR.rawValue)
        case .MediumDashed:
            return Int32(BORDERSTYLE_MEDIUMDASHED.rawValue)
        case .DashDot:
            return Int32(BORDERSTYLE_DASHDOT.rawValue)
        case .MediumDashDot:
            return Int32(BORDERSTYLE_MEDIUMDASHDOT.rawValue)
        case .DashDotDot:
            return Int32(BORDERSTYLE_DASHDOTDOT.rawValue)
        case .MediumDashDotDot:
            return Int32(BORDERSTYLE_MEDIUMDASHDOTDOT.rawValue)
        case .SlantDashDot:
            return Int32(BORDERSTYLE_SLANTDASHDOT.rawValue)
        }
    }

    static func from(raw: Int32) -> FormatBorderStyle
    {
        switch raw {
        case Int32(BORDERSTYLE_NONE.rawValue):
            return .None
        case Int32(BORDERSTYLE_THIN.rawValue):
            return .Thin
        case Int32(BORDERSTYLE_MEDIUM.rawValue):
            return .Medium
        case Int32(BORDERSTYLE_DASHED.rawValue):
            return .Dashed
        case Int32(BORDERSTYLE_DOTTED.rawValue):
            return .Dotted
        case Int32(BORDERSTYLE_THICK.rawValue):
            return .Thick
        case Int32(BORDERSTYLE_DOUBLE.rawValue):
            return .Double
        case Int32(BORDERSTYLE_HAIR.rawValue):
            return .Hair
        case Int32(BORDERSTYLE_MEDIUMDASHED.rawValue):
            return .MediumDashed
        case Int32(BORDERSTYLE_DASHDOT.rawValue):
            return .DashDot
        case Int32(BORDERSTYLE_MEDIUMDASHDOT.rawValue):
            return .MediumDashDot
        case Int32(BORDERSTYLE_DASHDOTDOT.rawValue):
            return .DashDotDot
        case Int32(BORDERSTYLE_MEDIUMDASHDOTDOT.rawValue):
            return .MediumDashDotDot
        case Int32(BORDERSTYLE_SLANTDASHDOT.rawValue):
            return .SlantDashDot
        default:
            fatalError("Invalid Border Style raw value")
        }
    }

}

fileprivate extension FormatVerticalAlignment {

    func toRaw() -> Int32
    {
        switch self {
        case .Top:
            return Int32(ALIGNV_TOP.rawValue)
        case .Center:
            return Int32(ALIGNV_CENTER.rawValue)
        case .Bottom:
            return Int32(ALIGNV_BOTTOM.rawValue)
        case .Justify:
            return Int32(ALIGNV_JUSTIFY.rawValue)
        case .Distributed:
            return Int32(ALIGNV_DISTRIBUTED.rawValue)
        }
    }

    static func from(raw: Int32) -> FormatVerticalAlignment
    {
        switch raw {
        case Int32(ALIGNV_TOP.rawValue):
            return .Top
        case Int32(ALIGNV_CENTER.rawValue):
            return .Center
        case Int32(ALIGNV_BOTTOM.rawValue):
            return .Bottom
        case Int32(ALIGNV_JUSTIFY.rawValue):
            return .Justify
        case Int32(ALIGNV_DISTRIBUTED.rawValue):
            return .Distributed
        default:
            fatalError("Invalid Vertical Alignment raw value")
        }
    }
}

fileprivate extension NumberFormat {

    func toRaw() -> Int32
    {
        switch self {
        case .General:
            return Int32(NUMFORMAT_GENERAL.rawValue)
        case .Text:
            return Int32(NUMFORMAT_TEXT.rawValue)
        case .Number(let decimalPoint, let thousandsSeparator):
            switch (decimalPoint, thousandsSeparator) {
            case (false, false):
                return Int32(NUMFORMAT_NUMBER.rawValue)
            case (true, true):
                return Int32(NUMFORMAT_NUMBER_SEP_D2.rawValue)
            case (true, false):
                return Int32(NUMFORMAT_NUMBER_D2.rawValue)
            case (false, true):
                return Int32(NUMFORMAT_NUMBER_SEP.rawValue)
            }
        case .NumberWithNegativesInBrackets(let decimalPoint, let negativesAreRed):
            switch (decimalPoint, negativesAreRed) {
            case (false, false):
                return Int32(NUMFORMAT_NUMBER_SEP_NEGBRA.rawValue)
            case (true, true):
                return Int32(NUMFORMAT_NUMBER_D2_SEP_NEGBRARED.rawValue)
            case (true, false):
                return Int32(NUMFORMAT_CURRENCY_D2_NEGBRA.rawValue)
            case (false, true):
                return Int32(NUMFORMAT_NUMBER_SEP_NEGBRARED.rawValue)
            }
        case .Currency(let decimalPoint, let negativesAreRed):
            switch (decimalPoint, negativesAreRed) {
            case (false, false):
                return Int32(NUMFORMAT_CURRENCY_NEGBRA.rawValue)
            case (true, true):
                return Int32(NUMFORMAT_CURRENCY_D2_NEGBRARED.rawValue)
            case (true, false):
                return Int32(NUMFORMAT_CURRENCY_D2_NEGBRA.rawValue)
            case (false, true):
                return Int32(NUMFORMAT_CURRENCY_NEGBRARED.rawValue)
            }
        case .Percent(let decimalPoint):
            if (decimalPoint) {
                return Int32(NUMFORMAT_PERCENT_D2.rawValue)
            } else {
                return Int32(NUMFORMAT_PERCENT.rawValue)
            }
        case .Scientific:
            return Int32(NUMFORMAT_SCIENTIFIC_D2.rawValue)
        case .ScientificAlternative:
            return Int32(NUMFORMAT_CUSTOM_000P0E_PLUS0.rawValue)
        case .Fraction(let withOneDigit):
            if (withOneDigit) {
                return Int32(NUMFORMAT_FRACTION_ONEDIG.rawValue)
            } else {
                return Int32(NUMFORMAT_FRACTION_TWODIG.rawValue)
            }
        case .Account(let decimalPoint, let currencySymbol):
            switch (decimalPoint, currencySymbol) {
            case (false, false):
                return Int32(NUMFORMAT_ACCOUNT.rawValue)
            case (false, true):
                return Int32(NUMFORMAT_ACCOUNTCUR.rawValue)
            case (true, false):
                return Int32(NUMFORMAT_ACCOUNT_D2.rawValue)
            case (true, true):
                return Int32(NUMFORMAT_ACCOUNT_D2_CUR.rawValue)
            }

        case .Date:
            return Int32(NUMFORMAT_DATE.rawValue)
        case .CustomDate(let format):
            switch format {
            case .DayMonth:
                return Int32(NUMFORMAT_CUSTOM_D_MON.rawValue)
            case .DayMonthYear:
                return Int32(NUMFORMAT_CUSTOM_D_MON_YY.rawValue)
            case .MonthYear:
                return Int32(NUMFORMAT_CUSTOM_MON_YY.rawValue)
            case .HoursMinutesAM:
                return Int32(NUMFORMAT_CUSTOM_HMM_AM.rawValue)
            case .HoursMinutes:
                return Int32(NUMFORMAT_CUSTOM_HMM.rawValue)
            case .HoursMinutesSecondsAM:
                return Int32(NUMFORMAT_CUSTOM_HMMSS_AM.rawValue)
            case .HoursMinutesSeconds:
                return Int32(NUMFORMAT_CUSTOM_HMMSS.rawValue)
            case .MinutesSeconds:
                return Int32(NUMFORMAT_CUSTOM_MMSS.rawValue)
            case .MonthDayYearHoursMinutes:
                return Int32(NUMFORMAT_CUSTOM_MDYYYY_HMM.rawValue)
            case .PrefixedHoursMinutesSeconds:
                return Int32(NUMFORMAT_CUSTOM_H0MMSS.rawValue)
            case .MinutesSecondsWithSuffix:
                return Int32(NUMFORMAT_CUSTOM_MMSS0.rawValue)
            }
        }
    }

    static func from(raw: Int32) -> NumberFormat
    {
        switch raw {
        case Int32(NUMFORMAT_GENERAL.rawValue):
            return .General

        case Int32(NUMFORMAT_NUMBER.rawValue):
            return .Number(decimalPoint: false, thousandsSeparator: false)
        case Int32(NUMFORMAT_NUMBER_D2.rawValue):
            return .Number(decimalPoint: true, thousandsSeparator: false)
        case Int32(NUMFORMAT_NUMBER_SEP.rawValue):
            return .Number(decimalPoint: false, thousandsSeparator: true)
        case Int32(NUMFORMAT_NUMBER_SEP_D2.rawValue):
            return .Number(decimalPoint: true, thousandsSeparator: true)

        case Int32(NUMFORMAT_CURRENCY_NEGBRA.rawValue):
            return .Currency(decimalPoint: false, negativesAreRed: false)
        case Int32(NUMFORMAT_CURRENCY_NEGBRARED.rawValue):
            return .Currency(decimalPoint: false, negativesAreRed: true)
        case Int32(NUMFORMAT_CURRENCY_D2_NEGBRA.rawValue):
            return .Currency(decimalPoint: true, negativesAreRed: false)
        case Int32(NUMFORMAT_CURRENCY_D2_NEGBRARED.rawValue):
            return .Currency(decimalPoint: true, negativesAreRed: true)

        case Int32(NUMFORMAT_PERCENT.rawValue):
            return .Percent(decimalPoint: false)
        case Int32(NUMFORMAT_PERCENT_D2.rawValue):
            return .Percent(decimalPoint: true)

        case Int32(NUMFORMAT_SCIENTIFIC_D2.rawValue):
            return .Scientific
        case Int32(NUMFORMAT_CUSTOM_000P0E_PLUS0.rawValue):
            return .ScientificAlternative

        case Int32(NUMFORMAT_FRACTION_ONEDIG.rawValue):
            return .Fraction(withOneDigit: true)
        case Int32(NUMFORMAT_FRACTION_TWODIG.rawValue):
            return .Fraction(withOneDigit: false)

        case Int32(NUMFORMAT_DATE.rawValue):
            return .Date

        case Int32(NUMFORMAT_CUSTOM_D_MON_YY.rawValue):
            return .CustomDate(format: .DayMonthYear)
        case Int32(NUMFORMAT_CUSTOM_D_MON.rawValue):
            return .CustomDate(format: .DayMonth)
        case Int32(NUMFORMAT_CUSTOM_MON_YY.rawValue):
            return .CustomDate(format: .MonthYear)
        case Int32(NUMFORMAT_CUSTOM_HMM_AM.rawValue):
            return .CustomDate(format: .HoursMinutesAM)
        case Int32(NUMFORMAT_CUSTOM_HMM.rawValue):
            return .CustomDate(format: .HoursMinutes)
        case Int32(NUMFORMAT_CUSTOM_HMMSS_AM.rawValue):
            return .CustomDate(format: .HoursMinutesSecondsAM)
        case Int32(NUMFORMAT_CUSTOM_HMMSS.rawValue):
            return .CustomDate(format: .HoursMinutesSeconds)
        case Int32(NUMFORMAT_CUSTOM_MDYYYY_HMM.rawValue):
            return .CustomDate(format: .MonthDayYearHoursMinutes)
        case Int32(NUMFORMAT_CUSTOM_MMSS.rawValue):
            return .CustomDate(format: .MinutesSeconds)
        case Int32(NUMFORMAT_CUSTOM_H0MMSS.rawValue):
            return .CustomDate(format: .PrefixedHoursMinutesSeconds)
        case Int32(NUMFORMAT_CUSTOM_MMSS0.rawValue):
            return .CustomDate(format: .MinutesSecondsWithSuffix)

        case Int32(NUMFORMAT_NUMBER_SEP_NEGBRA.rawValue):
            return .NumberWithNegativesInBrackets(decimalPoint: false, negativesAreRed: false)
        case Int32(NUMFORMAT_NUMBER_SEP_NEGBRARED.rawValue):
            return .NumberWithNegativesInBrackets(decimalPoint: false, negativesAreRed: true)
        case Int32(NUMFORMAT_NUMBER_D2_SEP_NEGBRA.rawValue):
            return .NumberWithNegativesInBrackets(decimalPoint: true, negativesAreRed: false)
        case Int32(NUMFORMAT_NUMBER_D2_SEP_NEGBRARED.rawValue):
            return .NumberWithNegativesInBrackets(decimalPoint: true, negativesAreRed: true)

        case Int32(NUMFORMAT_ACCOUNT.rawValue):
            return .Account(decimalPoint: false, currencySymbol: false)
        case Int32(NUMFORMAT_ACCOUNTCUR.rawValue):
            return .Account(decimalPoint: false, currencySymbol: true)
        case Int32(NUMFORMAT_ACCOUNT_D2.rawValue):
            return .Account(decimalPoint: true, currencySymbol: false)
        case Int32(NUMFORMAT_ACCOUNT_D2_CUR.rawValue):
            return .Account(decimalPoint: true, currencySymbol: true)

        case Int32(NUMFORMAT_TEXT.rawValue):
            return .Text

        default:
            fatalError("Invalid Number Format raw value")
        }
    }
}

// MARK: - Equatables -

public extension NumberFormat {

    static public func ==(lhs: NumberFormat, rhs: NumberFormat) -> Bool
    {
        switch (lhs, rhs) {
        case (.General, .General):
            return true
        case (.Text, .Text):
            return true
        case (let .Number(a, b), let .Number(c, d)):
            return (a == c) && (b == d)
        case (let .NumberWithNegativesInBrackets(a, b), let .NumberWithNegativesInBrackets(c, d)):
            return (a == c) && (b == d)
        case (let .Currency(a, b), let .Currency(c, d)):
            return (a == c) && (b == d)
        case (let .Percent(a), let .Percent(b)):
            return (a == b)
        case (.Scientific, .Scientific):
            return true
        case (.ScientificAlternative, .ScientificAlternative):
            return true
        case (let .Fraction(a), let .Fraction(b)):
            return (a == b)
        case (let .Account(a, b), let .Account(c, d)):
            return (a == c) && (b == d)
        case (.Date, .Date):
            return true
        case (let .CustomDate(a), let .CustomDate(b)):
            return (a == b)
        default:
            return false
        }
    }
}

public extension FormatDiagonalBorderType {

    static public func ==(lhs: FormatDiagonalBorderType, rhs: FormatDiagonalBorderType) -> Bool
    {
        switch (lhs, rhs) {
        case (.None, .None):
            return true
        case (.Up(let a, let b), .Up(let c, let d)),
             (.Down(let a, let b), .Down(let c, let d)),
             (.Both(let a, let b), .Both(let c, let d)):
            return (a == c) && (b == d)
        default:
            return false
        }
    }
}

public extension FormatFillPattern {

    static public func ==(lhs: FormatFillPattern, rhs: FormatFillPattern) -> Bool
    {
        switch (lhs, rhs) {
        case (.None, .None):
            return true
        case (.Solid(let a), .Solid(let b)):
            return (a == b)
        // I'm sorry
        case (.ThinHorizontalCrosshatch(let a, let b), .ThinHorizontalCrosshatch(let c, let d)),
             (.ThickDiagonalCrosshatch(let a, let b), .ThickDiagonalCrosshatch(let c, let d)),
             (.Gray25(let a, let b), .Gray25(let c, let d)),
             (.HorizontalStripes(let a, let b), .HorizontalStripes(let c, let d)),
             (.DiagonalStripes(let a, let b), .DiagonalStripes(let c, let d)),
             (.Gray12P5(let a, let b), .Gray12P5(let c, let d)),
             (.ThinDiagonalCrosshatch(let a, let b), .ThinDiagonalCrosshatch(let c, let d)),
             (.ThinHorizontalStripes(let a, let b), .ThinHorizontalStripes(let c, let d)),
             (.DiagonalCrosshatch(let a, let b), .DiagonalCrosshatch(let c, let d)),
             (.Gray50(let a, let b), .Gray50(let c, let d)),
             (.VerticalStripes(let a, let b), .VerticalStripes(let c, let d)),
             (.Gray75(let a, let b), .Gray75(let c, let d)),
             (.ThinDiagonalStripes(let a, let b), .ThinDiagonalStripes(let c, let d)),
             (.ReverseDiagonalStripes(let a, let b), .ReverseDiagonalStripes(let c, let d)),
             (.ThinVerticalStripes(let a, let b), .ThinVerticalStripes(let c, let d)),
             (.ThinReverseDiagonalStripes(let a, let b), .ThinReverseDiagonalStripes(let c, let d)),
             (.Gray6P25(let a, let b), .Gray6P25(let c, let d)):
            return (a == c) && (b == d)
        default:
            return false
        }
    }
}

public extension FormatTextRotation {

    static public func ==(lhs: FormatTextRotation, rhs: FormatTextRotation) -> Bool
    {
        switch (lhs, rhs) {
        case (.Vertical, .Vertical):
            return true
        case (.Clockwise(let a), .Clockwise(let b)):
            return a == b
        case (.Counterclockwise(let a), .Counterclockwise(let b)):
            return a == b
        default:
            return false
        }
    }
}
