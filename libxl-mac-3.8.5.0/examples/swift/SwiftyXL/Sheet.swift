//
//  Sheet.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 17/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public enum SheetError: Error {
    case InvalidCellType
    case InvalidComment
    case InternalError(message: String)
}

public enum SheetType {
    case Standart
    case Chart
    case Unknown
}

public class Sheet {
    let handle: SheetHandle
    public unowned let parentBook: Book

    init(withHandle handle: SheetHandle, parentBook: Book)
    {
        self.handle = handle
        self.parentBook = parentBook
    }

    /// Name of this sheet
    public var name: String {
        get {
            return String(utf8String: xlSheetNameA(handle))!
        }
        set {
            newValue.utf8CString.withUnsafeBufferPointer { xlSheetSetNameA(handle, $0.baseAddress) }
        }
    }

    /// Whether this sheet is protected or not
    public var protected: Bool {
        get {
            return Bool(xlSheetProtectA(handle) == 1)
        }
        set {
            xlSheetSetProtectA(handle, newValue ? 1 : 0)
        }
    }

    public enum HiddenStatus {
        // Sheet is visible
        case Visible
        // Sheet is hidden, but can be shown via the user interface
        case Hidden
        // Sheet is hidden and cannot be shown in the user interface
        case VeryHidden
    }

    /// Whether this sheet is hidden from user or not
    public var hidden: Sheet.HiddenStatus {
        get {
            return Sheet.HiddenStatus.from(raw: xlSheetHiddenA(handle))
        }
        set {
            xlSheetSetHiddenA(handle, newValue.toRaw())
        }
    }

    public enum EnhancedProtection {
        /// Default protection
        case Default
        /// Nothing is allowed except cell selections
        case All
        /// Objects are locked when the sheet is protected
        case Objects
        /// Scenarios are locked when the sheet is protected
        case Scenarios
        /// Formatting cells is allowed when the sheet is protected
        case FormattingCells
        /// Formatting columns is allowed when the sheet is protected
        case FormattingColumns
        /// Formatting rows is allowed when the sheet is protected
        case FormattingRows
        /// Inserting columns is allowed when the sheet is protected
        case InsertingColumns
        /// Inserting rows is allowed when the sheet is protected
        case InsertingRows
        /// Inserting hyperlinks is allowed when the sheet is protected
        case InsertingHyperlinks
        /// Deleting columns is allowed when the sheet is protected
        case DeletingColumns
        /// Deleting rows is allowed when the sheet is protected
        case DeletingRows
        /// Selection of locked cells is locked when the sheet is protected
        case SelectingLockedCells
        /// Sorting is allowed when the sheet is protected
        case Sorting
        /// Autofilters are allowed when the sheet is protected
        case Autofilters
        /// Pivot tables are allowed when the sheet is protected
        case PivotTables
        /// Selection of unlocked cells is locked when the sheet is protected
        case SelectingUnlockedCells
    }

    /// Protects the sheet with password and enchanced parameters
    public func set(enchancedProtections protections: [EnhancedProtection], password: String)
    {
        let flags = protections.reduce(0) { $0 | $1.toRaw() }
        password.utf8CString.withUnsafeBufferPointer {
            xlSheetSetProtectExA(handle, flags, $0.baseAddress, 1)
        }
    }

    /// Removes the specified protections from the sheet
    public func remove(enchancedProtections protections: [EnhancedProtection], password: String)
    {
        let flags = protections.reduce(0) { $0 | $1.toRaw() }
        password.utf8CString.withUnsafeBufferPointer {
            xlSheetSetProtectExA(handle, flags, $0.baseAddress, 0)
        }
    }

    public enum WritingDirection: Int32 {
        case leftToRight = 0 // Left to right writing direction
        case rightToLeft = 1 // Right to left writing direction
    }

    /// Writing directions for the text in this sheet
    public var writingDirection: Sheet.WritingDirection {
        get {
            return Sheet.WritingDirection(rawValue: xlSheetRightToLeftA(handle))!
        }
        set {
            xlSheetSetRightToLeftA(handle, newValue.rawValue)
        }
    }

    public enum CellType {
        case Empty
        case Number
        case String
        case Boolean
        case Blank
    }

    public func type(forCellAtRow row: Int, column: Int) throws -> Sheet.CellType
    {
        let raw = xlSheetCellTypeA(handle, Int32(row), Int32(column))
        if raw == Sheet.CellType.errorType() {
            throw SheetError.InvalidCellType
        }
        return Sheet.CellType.from(rawValue: raw)
    }

    public func containsFormula(atRow row: Int, column: Int) -> Bool
    {
        return xlSheetIsFormulaA(handle, Int32(row), Int32(column)) == 1
    }

    public func containsDate(at cell: (row: Int, column: Int)) -> Bool
    {
        return Bool(xlSheetIsDateA(handle, Int32(cell.0), Int32(cell.1)) == 1)
    }

    // MARK: - Comments

    public func comment(forCellAtRow row: Int, column: Int) -> String?
    {
        let raw: UnsafePointer<Int8>? = xlSheetReadCommentA(handle, Int32(row), Int32(column))
        return raw.map { String(cString: $0) }
    }

    public func write(comment: String, forCellAtRow row: Int, column: Int, textBoxSize size: NSSize)
    {
        comment.utf8CString.withUnsafeBufferPointer { commentBuffer in
            "".utf8CString.withUnsafeBufferPointer { authorBuffer in
                xlSheetWriteCommentA(handle, Int32(row), Int32(column),
                                     commentBuffer.baseAddress, authorBuffer.baseAddress,
                                     Int32(size.width), Int32(size.height))
            }
        }
    }

    public func remove(commentForCellAtRow row: Int, column: Int)
    {
        xlSheetRemoveCommentA(handle, Int32(row), Int32(column))
    }

    // MARK: - Cell Formats

    public func format(forCellAtRow row: Int, column: Int) -> Format?
    {
        let maybeFormatHandle: FormatHandle? = xlSheetCellFormatA(handle, Int32(row), Int32(column))
        return maybeFormatHandle.map { Format(withHandle: $0)}
    }

    public func set(format: Format, forCellAtRow row: Int, column: Int)
    {
        xlSheetSetCellFormatA(handle, Int32(row), Int32(column), format.handle)
    }


    // MARK: - Auto Filters

    public var autoFilter: AutoFilter? {
        get {
            return (xlSheetAutoFilterA(handle) as AutoFilterHandle?).map {
                AutoFilter(handle: $0)
            }
        }
    }

    public func applyAutoFilter()
    {
        xlSheetApplyFilterA(handle)
    }

    public func removeAutoFilter()
    {
        xlSheetRemoveFilterA(handle)
    }

    // MARK: - Reading & Writing


    public enum CellValue {
        case Date(value: Date, format: Format)
        case Number(value: Double, format: Format)
        case Boolean(value: Bool, format: Format)
        case String(value: String)
        case Blank(format: Format)
        case Empty
    }

    public func read(valueForCell cell: (row: Int, column: Int)) -> Sheet.CellValue?
    {
        let row = cell.0, column = cell.1

        guard let type = try? type(forCellAtRow: row, column: column) else {
            return nil
        }
        switch type {
        case .Number:
            var formatHandle: FormatHandle? = nil
            let number = xlSheetReadNumA(handle, Int32(row), Int32(column), &formatHandle)
            guard let reallyFormatHandle = formatHandle else {
                return nil
            }
            let format = Format(withHandle: reallyFormatHandle)
            switch format.numberFormat {
            case .Date, .CustomDate(_):
                if let date: Date = parentBook.unpack(date: number),
                    containsDate(at: (row, column)) {
                    return .Date(value: date, format: format)
                }
                fallthrough
            default:
                return .Number(value: number, format: format)
            }
        case .String:
            var formatHandle: FormatHandle? = nil
            let rawString = xlSheetReadStrA(handle, Int32(row), Int32(column), &formatHandle)
            guard let string = rawString else {
                return nil
            }
            return .String(value: String(utf8String: string)!)
        case .Boolean:
            var formatHandle: FormatHandle? = nil
            let boolean = xlSheetReadBoolA(handle, Int32(row), Int32(column), &formatHandle)
            guard let reallyFormatHandle = formatHandle else {
                return nil
            }
            return .Boolean(value: Bool(boolean == 1), format: Format(withHandle: reallyFormatHandle))
        case .Blank:
            var formatHandle: FormatHandle? = nil
            let status = xlSheetReadBlankA(handle, Int32(row), Int32(column), &formatHandle)
            guard status != 0, let reallyFormatHandle = formatHandle else {
                return nil
            }
            return .Blank(format: Format(withHandle: reallyFormatHandle))
        case .Empty:
            return .Empty
        }
    }

    @discardableResult public func write<T>(value: T?, toCell cell: (row: Int, column: Int), withFormat format: Format? = nil) -> Bool
    {
        let row = cell.0, column = cell.1
        let status: Int32

        switch value {
        case let integerValue as Int:
            status = xlSheetWriteNumA(handle, Int32(row), Int32(column), Double(integerValue), format?.handle)
        case let floatValue as Float:
            status = xlSheetWriteNumA(handle, Int32(row), Int32(column), Double(floatValue), format?.handle)
        case let doubleValue as Double:
            status = xlSheetWriteNumA(handle, Int32(row), Int32(column), doubleValue, format?.handle)
        case let dateValue as Date:
            // We need a special format for a date value,
            // otherwise it will be written as a plain number
            guard let dateFormat = dataNumberFormat(fromFormat: format) else {
                return false
            }
            status = xlSheetWriteNumA(handle, Int32(row), Int32(column),
                                      parentBook.pack(date: dateValue), dateFormat.handle)
        case let stringValue as String:
            status = stringValue.utf8CString.withUnsafeBufferPointer {
                return xlSheetWriteStrA(handle, Int32(row), Int32(column), $0.baseAddress, format?.handle)
            } ?? 0
        case let booleanValue as Bool:
            status = xlSheetWriteBoolA(handle, Int32(row), Int32(column), Int32(booleanValue ? 1 : 0), format?.handle)
        default:
            // It's a blank value so we're only interested in a format
            status = xlSheetWriteBlankA(handle, Int32(row), Int32(column), format?.handle)
        }

        return Bool(status != 0)
    }

    private func dataNumberFormat(fromFormat origin: Format?) -> Format?
    {
        guard let dateFormat = origin ?? (try? parentBook.add(formatByCopying: origin)) else {
            return nil
        }
        switch dateFormat.numberFormat {
        case .Date, .CustomDate(_):
            // Alright, it's already a date format
            break
        default:
            dateFormat.numberFormat = .Date
        }
        return dateFormat
    }

    // MARK: - Formulas

    @discardableResult public func write(formula: String, toCell cell: (row: Int, column: Int), format: Format? = nil) -> Bool
    {
        let row = cell.0, column = cell.1
        return Bool(1 == formula.utf8CString.withUnsafeBufferPointer {
            xlSheetWriteFormulaA(handle, Int32(row), Int32(column), $0.baseAddress, format?.handle)
        })
    }

    @discardableResult public func write<T>(formula: String, toCell cell: (row: Int, column: Int), withPrecalculatedResult precalculated: T, format: Format? = nil) -> Bool
    {
        let row = cell.0, column = cell.1
        return Bool(Int32(1) == formula.utf8CString.withUnsafeBufferPointer { formulaBuffer in
            switch precalculated {
            case let integerValue as Int:
                return xlSheetWriteFormulaNumA(handle, Int32(row), Int32(column),
                                               formulaBuffer.baseAddress, Double(integerValue), format?.handle)
            case let floatValue as Float:
               return xlSheetWriteFormulaNumA(handle, Int32(row), Int32(column),
                                              formulaBuffer.baseAddress, Double(floatValue), format?.handle)
            case let doubleValue as Double:
                return xlSheetWriteFormulaNumA(handle, Int32(row), Int32(column),
                                               formulaBuffer.baseAddress, doubleValue, format?.handle)
            case let booleanValue as Bool:
                return xlSheetWriteFormulaBoolA(handle, Int32(row), Int32(column),
                                                formulaBuffer.baseAddress, Int32(booleanValue ? 1 : 0), format?.handle)
            case let stringValue as String:
                return stringValue.utf8CString.withUnsafeBufferPointer { valueBuffer in
                    return xlSheetWriteFormulaStrA(handle, Int32(row), Int32(column),
                                                   formulaBuffer.baseAddress, valueBuffer.baseAddress,
                                                   format?.handle)
                }
            case let dateValue as Date:
                let dateAsNumber = parentBook.pack(date: dateValue)
                return xlSheetWriteFormulaNumA(handle, Int32(row), Int32(column),
                                               formulaBuffer.baseAddress, dateAsNumber, format?.handle)
            default:
                return Int32(0)
            }
        })
    }

    public func read(formulaFromCell cell: (row: Int, column: Int)) -> String?
    {
        let row = cell.0, column = cell.1
        let rawResult: UnsafePointer<Int8>? = xlSheetReadFormulaA(handle, Int32(row), Int32(column), nil)
        return rawResult.flatMap { String(utf8String: $0) }
    }

    public enum CalculationError {
        case Null
        case DivisionByZero
        case Value
        case Reference
        case Name
        case Number
        case NA
        case NoError
    }

    public func write(error: CalculationError, toCell cell: (row: Int, column: Int), format: Format? = nil)
    {
        let row = cell.0, column = cell.1
        xlSheetWriteErrorA(handle, Int32(row), Int32(column), error.toRaw(), format?.handle)
    }

    public func read(errorFromCell cell: (row: Int, column: Int)) -> CalculationError
    {
        let row = cell.0, column = cell.1
        return CalculationError.from(raw: xlSheetReadErrorA(handle, Int32(row), Int32(column)))
    }

    // MARK: - Columns, Rows

    public func width(ofColumn column: Int) -> Double
    {
        return xlSheetColWidthA(handle, Int32(column))
    }

    public func height(ofRow row: Int) -> Double
    {
        return xlSheetRowHeightA(handle, Int32(row))
    }

    /// Represents a column width which may be calculated automatically to fit
    /// this column's contents or have an explicit Double value set by user.
    public enum ColumnWidth {
        case Auto
        case Exactly(_: Double)
    }

    public func set(width: Sheet.ColumnWidth, forColumn column: Int, hidden: Bool, format: Format? = nil) throws
    {
        try set(width: width, forColumns: column...column, hidden: hidden, format: format)
    }

    public func set(width: Sheet.ColumnWidth, forColumns columns: CountableClosedRange<Int>, hidden: Bool, format: Format? = nil) throws
    {
        let rawWidth = width.toRaw()
        let status = xlSheetSetColA(handle, Int32(columns.lowerBound), Int32(columns.upperBound), rawWidth, format?.handle, Int32(hidden ? 1 : 0))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Sets the borders for autofit column widths feature
    public func set(autoFitArea area: Sheet.CellRange)
    {
        xlSheetSetAutoFitAreaA(handle, Int32(area.rows.lowerBound), Int32(area.rows.upperBound),
                               Int32(area.columns.lowerBound), Int32(area.columns.upperBound))
    }

    public func set(height: Double, forRow row: Int, hidden: Bool, format: Format? = nil) throws
    {
        let status = xlSheetSetRowA(handle, Int32(row), height, format?.handle, Int32(hidden ? 1 : 0))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    public func hidden(row: Int) -> Bool
    {
        return Bool(xlSheetRowHiddenA(handle, Int32(row)) == 1)
    }

    public func hide(row: Int)
    {
        xlSheetSetRowHiddenA(handle, Int32(row), Int32(1))
    }

    public func hidden(column: Int) -> Bool
    {
        return Bool(xlSheetColHiddenA(handle, Int32(column)) == 1)
    }

    public func hide(column: Int)
    {
        xlSheetSetColHiddenA(handle, Int32(column), Int32(1))
    }

    public func show(row: Int)
    {
        xlSheetSetRowHiddenA(handle, Int32(row), Int32(0))
    }

    public func show(column: Int)
    {
        xlSheetSetColHiddenA(handle, Int32(column), Int32(0))
    }

    // MARK: - Merges

    public struct CellRange: Equatable {
        public let rows: CountableClosedRange<Int>
        public let columns: CountableClosedRange<Int>

        public init(rows: CountableClosedRange<Int>, columns: CountableClosedRange<Int>)
        {
            self.rows = rows
            self.columns = columns
        }

        public static func ==(lhs: CellRange, rhs: CellRange) -> Bool
        {
            return (lhs.rows == rhs.rows) && (lhs.columns == rhs.columns)
        }
    }

    /// Returns a range of merged cells containing the given cell or nil if it's not merged
    /// with any other cell
    public func rangeOfMergedCells(containingCell cell: (row: Int, column: Int)) -> Sheet.CellRange?
    {
        let row = Int32(cell.0), column = Int32(cell.1)
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        let status = xlSheetGetMergeA(handle, row, column, &rowFirst, &rowLast, &colFirst, &colLast)
        guard status == 1 else {
            return nil
        }
        return Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                           columns: Int(colFirst)...Int(colLast))
    }

    /// Merges cells in a given cell range
    public func merge(cells: Sheet.CellRange) throws
    {
        let status = xlSheetSetMergeA(handle, Int32(cells.rows.lowerBound), Int32(cells.rows.upperBound), Int32(cells.columns.lowerBound), Int32(cells.columns.upperBound))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Removes merged cells
    public func delete(mergeContainingCell cell: (row: Int, column: Int)) throws
    {
        let row = Int32(cell.0), column = Int32(cell.1)
        let status = xlSheetDelMergeA(handle, row, column)
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Returns a number of merged cells in this worksheet
    public var numberOfMergedCells: Int {
        get {
            return Int(xlSheetMergeSizeA(handle))
        }
    }

    /// Returns a range of merged cells by index
    public func rangeOfMergedCells(atIndex index: Int) -> Sheet.CellRange?
    {
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        let status = xlSheetMergeA(handle, Int32(index), &rowFirst, &rowLast, &colFirst, &colLast)
        guard status == 1 else {
            return nil
        }
        return Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                               columns: Int(colFirst)...Int(colLast))
    }

    /// Removes merged cells by index
    @discardableResult public func delete(mergedCellsAtIndex index: Int) -> Bool
    {
        return Bool(xlSheetDelMergeByIndexA(handle, Int32(index)) == 1)
    }

    // MARK: - Pictures

    public var numberOfPictures: Int {
        get {
            return Int(xlSheetPictureSizeA(handle))
        }
    }

    public struct PictureLocation {
        /// Workbook-wise identifier of this picture
        public let identifier: PictureIdentiifer
        /// Top left position of picture;
        public let topLeft: (topRow: Int, leftColumn: Int)
        /// Bottom right position of picture;
        public let bottomRight: (bottomRow: Int, rightColumn: Int)
        /// Width in pixels
        public let width: Int
        /// Height in pixels
        public let height: Int
        /// Horizontal offset in pixels
        public let xOffset: Int
        /// Vertical offset in pixels
        public let yOffset: Int
    }

    /// Returns a workbook picture index at position index in worksheet.
    /// Use Book.picture(atIndex:) for extacting binary data of a picture
    /// by workbook picture index.
    public func pictureLocation(atIndex index: Int) throws -> Sheet.PictureLocation
    {
        var rowTop: Int32 = 0, colLeft: Int32 = 0, rowBottom: Int32 = 0, colRight: Int32 = 0
        var width: Int32 = 0, height: Int32 = 0
        var offset_x: Int32 = 0, offset_y: Int32 = 0

        let id = xlSheetGetPictureA(handle, Int32(index), &rowTop, &colLeft, &rowBottom, &colRight, &width, &height, &offset_x, &offset_y)
        if id == -1 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
        return Sheet.PictureLocation(identifier: PictureIdentiifer(id),
                                     topLeft: (Int(rowTop), Int(colLeft)),
                                     bottomRight: (Int(rowBottom), Int(colRight)),
                                     width: Int(width), height: Int(height),
                                     xOffset: Int(offset_x), yOffset: Int(offset_y))
    }

    /// Sets a picture with the given identifier at position row and column with scale factor
    /// and offsets in pixels
    public func set(picture id: PictureIdentiifer, at: (row: Int, column: Int), scale: Double = 1.0, offsets: (xOffset: Int, yOffset: Int) = (0,0))
    {
        let row = Int32(at.0), column = Int32(at.1)
        let offset_x = Int32(offsets.0), offset_y = Int32(offsets.1)
        xlSheetSetPictureA(handle, row, column, Int32(id), scale, offset_x, offset_y, 0)
    }

    /// Sets a picture with pictureId identifier at position row and col with custom size and offsets in pixels
    public func set(picture id: PictureIdentiifer, at: (row: Int, column: Int), width: Int, height: Int, offsets: (xOffset: Int, yOffset: Int) = (0,0))
    {
        let row = Int32(at.0), column = Int32(at.1)
        let offset_x = Int32(offsets.0), offset_y = Int32(offsets.1)
        xlSheetSetPicture2A(handle, row, column, Int32(id), Int32(width), Int32(height), offset_x, offset_y, 0)
    }

    // MARK: - Page Breaks

    /// Returns row with horizontal page break at position index or (-1) if the
    /// given index is not valid
    public func rowWithHorizontalPageBreak(atIndex index: Int) -> Int
    {
        return Int(xlSheetGetHorPageBreakA(handle, Int32(index)))
    }

    /// Returns a number of horizontal page breaks in the sheet.
    public var numberOfHorizontalPageBreaks: Int {
        get {
            return Int(xlSheetGetHorPageBreakSizeA(handle))
        }
    }

    /// Adds a new horizontal page break at the given row
    public func add(horizontalPageBreakAtRow row: Int) throws
    {
        let status = xlSheetSetHorPageBreakA(handle, Int32(row), 1)
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Removes a horizontal page break from the given row
    public func remove(horizontalPageBreakAtRow row: Int) throws
    {
        let status = xlSheetSetHorPageBreakA(handle, Int32(row), Int32(0))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Returns column with vertical page break at position index
    public func columnWithVerticalPageBreak(atIndex index: Int) -> Int
    {
        return Int(xlSheetGetVerPageBreakA(handle, Int32(index)))
    }

    /// Returns a number of vertical page breaks in the sheet
    public var numberOfVerticalPageBreaks: Int {
        get {
            return Int(xlSheetGetVerPageBreakSizeA(handle))
        }
    }

    /// Adds a new vertical page break at the given column
    public func add(verticalPageBreakAtColumn column: Int) throws
    {
        let status = xlSheetSetVerPageBreakA(handle, Int32(column), 1)
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Removes a vertical page break from the given column
    public func remove(verticalPageBreakAtColumn column: Int) throws
    {
        let status = xlSheetSetVerPageBreakA(handle, Int32(column), 0)
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    // MARK: - Splits

    /// Splits a sheet at position (row, column) or specifies the position of frozen pane.
    /// This function allows to freeze a header at top position or freeze some columns on the right
    public func split(sheetAtPosition position: (row: Int, column: Int))
    {
        xlSheetSplitA(handle, Int32(position.0), Int32(position.1))
    }

    /// Gets the split information (position of frozen pane) in the sheet
    public var splitPosition: (row: Int, column: Int) {
        get {
            var row: Int32 = 0, column: Int32 = 0
            xlSheetSplitInfoA(handle, &row, &column)
            return (Int(row), Int(column))
        }
    }

    // MARK: - Grouping

    /// Groups rows in the given range. This new group can optionally be collapsed.
    public func group(rows: CountableClosedRange<Int>, collapsing: Bool) throws
    {
        let status = xlSheetGroupRowsA(handle, Int32(rows.lowerBound), Int32(rows.upperBound),
                                       Int32(collapsing ? 1 : 0))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Groups columns in the given range. This new group can optionally be collapsed.
    public func group(columns: CountableClosedRange<Int>, collapsing: Bool) throws
    {
        let status = xlSheetGroupColsA(handle, Int32(columns.lowerBound), Int32(columns.upperBound),
                                       Int32(collapsing ? 1 : 0))
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    public enum GroupingSummaryVerticalLocation: Int32 {
        case Below = 1
        case Above = 0
    }

    /// Returns a grouping summary vertical position
    public var groupingSummaryVerticalLocation: Sheet.GroupingSummaryVerticalLocation {
        get {
            return Sheet.GroupingSummaryVerticalLocation(rawValue: xlSheetGroupSummaryBelowA(handle))!
        }
        set {
            xlSheetSetGroupSummaryBelowA(handle, newValue.rawValue)
        }
    }

    public enum GroupingSummaryHorizontalPosition: Int32 {
        case Right = 1
        case Left = 0
    }

    /// Returns a grouping summary horizontal position
    public var groupingSummaryHorizontalLocation: Sheet.GroupingSummaryHorizontalPosition {
        get {
            return Sheet.GroupingSummaryHorizontalPosition(rawValue: xlSheetGroupSummaryRightA(handle))!
        }
        set {
            xlSheetSetGroupSummaryRightA(handle, newValue.rawValue)
        }
    }

    // MARK: - Cell Manipulations

    /// Clears cells in the specified range
    public func clear(cells: Sheet.CellRange)
    {
        xlSheetClearA(handle, Int32(cells.rows.lowerBound), Int32(cells.rows.upperBound),
                      Int32(cells.columns.lowerBound), Int32(cells.columns.upperBound))
    }

    /// Inserts rows from the given range
    public func insert(rows: CountableClosedRange<Int>) throws
    {
        if xlSheetInsertRowA(handle, Int32(rows.lowerBound), Int32(rows.upperBound)) == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Inserts a single row
    public func insert(row: Int) throws
    {
        try insert(rows: row...row)
    }

    /// Inserts columns from the given range
    public func insert(columns: CountableClosedRange<Int>) throws
    {
        if xlSheetInsertColA(handle, Int32(columns.lowerBound), Int32(columns.upperBound)) == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Inserts a single column
    public func insert(column: Int) throws
    {
        try insert(columns: column...column)
    }

    /// Removes rows from the given range
    public func remove(rows: CountableClosedRange<Int>) throws
    {
        if xlSheetRemoveRowA(handle, Int32(rows.lowerBound), Int32(rows.upperBound)) == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }
    /// Removes a single row
    public func remove(row: Int) throws
    {
        try remove(rows: row...row)
    }

    /// Removes columns from the given range
    public func remove(columns: CountableClosedRange<Int>) throws
    {
        if xlSheetRemoveColA(handle, Int32(columns.lowerBound), Int32(columns.upperBound)) == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    /// Removes a single column
    public func remove(column: Int) throws
    {
        try remove(columns: column...column)
    }

    /// Copies a cell with its format
    public func copy(cell: (sourceRow: Int, sourceColumn: Int), to: (targetRow: Int, targetColumn: Int)) throws
    {
        if xlSheetCopyCellA(handle, Int32(cell.sourceRow), Int32(cell.sourceColumn),
                            Int32(to.targetRow), Int32(to.targetColumn)) == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    // MARK: - General Information

    /// Returns the first row in the sheet that contains a used cell
    public var firstUsedRow: Int {
        get {
            return Int(xlSheetFirstRowA(handle))
        }
    }

    /// Returns the zero-based index of the row after the last row in the sheet
    /// that contains a used cell
    public var lastUsedRow: Int {
        get {
            return Int(xlSheetLastRowA(handle))
        }
    }

    /// Returns the first column in the sheet that contains a used cell
    public var firstUsedColumn: Int {
        get {
            return Int(xlSheetFirstColA(handle))
        }
    }

    /// Returns the zero-based index of the column after the last column in the sheet
    /// that contains a used cell
    public var lastUsedColumn: Int {
        get {
            return Int(xlSheetLastColA(handle))
        }
    }

    // MARK: - Printing

    /// Whether the gridlines are displayed or not
    public var displayGridlines: Bool {
        get {
            return Bool(xlSheetDisplayGridlinesA(handle) == 1)
        }
        set {
            xlSheetSetDisplayGridlinesA(handle, Int32(newValue ? 1 : 0))
        }
    }

    /// Whether the gridlines should be printed or not
    public var printGridlines: Bool {
        get {
            return Bool(xlSheetPrintGridlinesA(handle) == 1)
        }
        set {
            xlSheetSetPrintGridlinesA(handle, Int32(newValue ? 1 : 0))
        }
    }

    /// A zoom level that represents a usual non-scaled view
    static let defaultZoomLevel = 100

    /// A zoom level of the current view (as a percentage)
    public var zoomLevel: UInt {
        get {
            return UInt(xlSheetZoomA(handle))
        }
        set {
            xlSheetSetZoomA(handle, Int32(newValue))
        }
    }

    // A scaling factor of the current view for printing (as a percentage)
    public var printZoomLevel: UInt {
        get {
            return UInt(xlSheetPrintZoomA(handle))
        }
        set {
            xlSheetSetPrintZoomA(handle, Int32(newValue))
        }
    }

    public struct FitToPagePrintingOptions: Equatable
    {
        public let enabled: Bool
        public let widthInPages: Int
        public let heightInPages: Int

        public init(enabled: Bool, widthInPages: Int, heightInPages: Int)
        {
            self.enabled = enabled
            self.widthInPages = widthInPages
            self.heightInPages = heightInPages
        }

        public static func ==(lhs: Sheet.FitToPagePrintingOptions, rhs: Sheet.FitToPagePrintingOptions) -> Bool
        {
            return (lhs.enabled == rhs.enabled) && (lhs.widthInPages == rhs.widthInPages) && (lhs.heightInPages == rhs.heightInPages)
        }
    }

    // Fit to page options for printing
    public var fitToPagePrintingOptions: Sheet.FitToPagePrintingOptions {
        get {
            var wPages: Int32 = 0, hPages: Int32 = 0
            let enabled = Bool(xlSheetGetPrintFitA(handle, &wPages, &hPages) == 1)
            return Sheet.FitToPagePrintingOptions(enabled: enabled, widthInPages: Int(wPages),
                                                  heightInPages: Int(hPages))
        }
        set {
            xlSheetSetPrintFitA(handle, Int32(newValue.widthInPages), Int32(newValue.heightInPages))
        }
    }

    public enum PageOrientationForPrinting: Int32 {
        case Landscape = 1
        case Portrait = 0
    }

    /// A page orientation in which this sheet is going to be printed
    public var pageOrientation: Sheet.PageOrientationForPrinting {
        get {
            return Sheet.PageOrientationForPrinting(rawValue: xlSheetLandscapeA(handle))!
        }
        set {
            xlSheetSetLandscapeA(handle, newValue.rawValue)
        }
    }

    public enum PaperSize {
        /// Default paper size
        case Default
        /// US Letter 8 1/2 x 11 in
        case Letter
        /// US Letter Small 8 1/2 x 11 in
        case LetterSmall
        /// US Tabloid 11 x 17 in
        case Tabloid
        /// US Ledger 17 x 11 in
        case Ledger
        /// US Legal 8 1/2 x 14 in
        case Legal
        /// US Statement 5 1/2 x 8 1/2 in
        case Statement
        /// US Executive 7 1/4 x 10 1/2 in
        case Executive
        /// A3 297 x 420 mm
        case A3
        /// A4 210 x 297 mm
        case A4
        /// A4 Small 210 x 297 mm
        case A4Small
        /// A5 148 x 210 mm
        case A5
        /// B4 (JIS) 250 x 354
        case B4
        /// B5 (JIS) 182 x 257 mm
        case B5
        /// Folio 8 1/2 x 13 in
        case Folio
        /// Quarto 215 x 275 mm
        case Quatro
        /// 10 x 14 in
        case Inches10x14
        /// 11 x 17 in
        case Inches10x17
        /// US Note 8 1/2 x 11 in
        case Note
        /// US Envelope #9 3 7/8 x 8 7/8
        case Envelope9
        /// US Envelope #10 4 1/8 x 9 1/2
        case Envelope10
        /// US Envelope #11 4 1/2 x 10 3/8
        case Envelope11
        /// US Envelope #12 4 3/4 x 11
        case Envelope12
        /// US Envelope #14 5 x 11 1/2
        case Envelope14
        /// C size sheet
        case CSize
        /// D size sheet
        case Dsize
        /// E size sheet
        case ESize
        /// Envelope 110 x 230 mm
        case Envelope
        /// Envelope DL 110 x 220mm
        case EnvelopeDL
        ///	Envelope C3 324 x 458 mm
        case EnvelopeC3
        /// Envelope C4 229 x 324 mm
        case EnvelopeC4
        /// Envelope C5 162 x 229 mm
        case EnvelopeC5
        /// Envelope C6 114 x 162 mm
        case EnvelopeC6
        /// Envelope C65 114 x 229 mm
        case EnvelopeC65
        /// Envelope B4 250 x 353 mm
        case EnvelopeB4
        /// Envelope B5 176 x 250 mm
        case EnvelopeB5
        /// Envelope B6 176 x 125 mm
        case EnvelopeB6
        /// US Envelope Monarch 3.875 x 7.5 in
        case EnvelopeMonarch
        /// US Envelope 3 5/8 x 6 1/2 in
        case EnvelopeUS
        /// US Std Fanfold 14 7/8 x 11 in
        case Fanfold
        /// German Std Fanfold 8 1/2 x 12 in
        case GermanStandartFanfold
        /// German Legal Fanfold 8 1/2 x 13 in
        case GermanLegalFanfold
    }

    /// A paper size used for printing this sheet
    public var paperSize: Sheet.PaperSize {
        get {
            return Sheet.PaperSize.from(raw: xlSheetPaperA(handle))
        }
        set {
            xlSheetSetPaperA(handle, newValue.toRaw())
        }
    }

    // MARK: - Header and Footer

    public struct Header: Equatable {
        // The length of the text must be less than or equal to 255. It may also contain special
        // commands, for example a placeholder for the page number, current date or text formatting
        // attributes. See documentation for details: http://www.libxl.com/spreadsheet.html?lang=c#setHeader
        public let format: String
        // Margin in inches
        public let margin: Double

        public init(format: String, margin: Double)
        {
            self.format = format
            self.margin = margin
        }

        public static func ==(lhs: Sheet.Header, rhs: Sheet.Header) -> Bool
        {
            return (lhs.format == rhs.format) && (lhs.margin == rhs.margin)
        }
    }

    /// Sets the header of the sheet when printed
    public var header: Sheet.Header? {
        get {
            let rawHeaderFormat: UnsafePointer<Int8>? = xlSheetHeaderA(handle)
            return rawHeaderFormat.flatMap({String(utf8String: $0)}).map {
                Sheet.Header(format: $0, margin: xlSheetHeaderMarginA(handle))
            }
        }
        set {
            guard let actuallyHeader = newValue else {
                return
            }
            _ = actuallyHeader.format.utf8CString.withUnsafeBufferPointer {
                xlSheetSetHeaderA(handle, $0.baseAddress, actuallyHeader.margin)
            }
        }
    }

    public typealias Footer = Header

    /// Sets the footer of the sheet when printed
    public var footer: Sheet.Footer? {
        get {
            let rawFooterFormat: UnsafePointer<Int8>? = xlSheetFooterA(handle)
            return rawFooterFormat.flatMap({ String(utf8String: $0)}).map {
                Sheet.Footer(format: $0, margin: xlSheetFooterMarginA(handle))
            }
        }
        set {
            guard let actuallyFooter = newValue else {
                return
            }
            _ = actuallyFooter.format.utf8CString.withUnsafeBufferPointer {
                xlSheetSetFooterA(handle, $0.baseAddress, actuallyFooter.margin)
            }
        }
    }

    /// Center the sheet horizontally when printing
    public var centerHorizontally: Bool {
        get {
            return Bool(xlSheetHCenterA(handle) == 1)
        }
        set {
            xlSheetSetHCenterA(handle, newValue ? 1 : 0)
        }
    }

    /// Center the sheet vertically when printing
    public var centerVertically: Bool {
        get {
            return Bool(xlSheetVCenterA(handle) == 1)
        }
        set {
            xlSheetSetVCenterA(handle, newValue ? 1 : 0)
        }
    }

    /// Left margin of the sheet in inches
    public var leftMargin: Double {
        get {
            return xlSheetMarginLeftA(handle)
        }
        set {
            xlSheetSetMarginLeftA(handle, newValue)
        }
    }

    /// Right margin of the sheet in inches
    public var rightMargin: Double {
        get {
            return xlSheetMarginRightA(handle)
        }
        set {
            xlSheetSetMarginRightA(handle, newValue)
        }
    }

    /// Top margin of the sheet in inches
    public var topMargin: Double {
        get {
            return xlSheetMarginTopA(handle)
        }
        set {
            xlSheetSetMarginTopA(handle, newValue)
        }
    }

    /// Bottom margin of the sheet in inches
    public var bottomMargin: Double {
        get {
            return xlSheetMarginBottomA(handle)
        }
        set {
            xlSheetSetMarginBottomA(handle, newValue)
        }
    }

    /// Print row and column headers
    public var printRowColumnHeader: Bool {
        get {
            return Bool(xlSheetPrintRowColA(handle) == 1)
        }
        set {
            xlSheetSetPrintRowColA(handle, newValue ? 1 : 0)
        }
    }

    /// Rows that are repeated on each page when printing
    public var repeatedRows: CountableClosedRange<Int>? {
        get {
            var rowFirst: Int32 = 0, rowLast: Int32 = 0
            if xlSheetPrintRepeatRowsA(handle, &rowFirst, &rowLast) == 0 {
                return nil
            }
            return Int(rowFirst)...Int(rowLast)
        }
        set {
            guard let rows = newValue else {
                return
            }
            xlSheetSetPrintRepeatRowsA(handle, Int32(rows.lowerBound), Int32(rows.upperBound))
        }
    }

    /// Columns that are repeated on each page when printing
    public var repeatedColumns: CountableClosedRange<Int>? {
        get {
            var colFirst: Int32 = 0, colLast: Int32 = 0
            if xlSheetPrintRepeatColsA(handle, &colFirst, &colLast) == 0 {
                return nil
            }
            return Int(colFirst)...Int(colLast)
        }
        set {
            guard let columns = newValue else {
                return
            }
            xlSheetSetPrintRepeatColsA(handle, Int32(columns.lowerBound), Int32(columns.upperBound))
        }
    }

    /// Clears repeated rows and columns on each page
    public func clearPrintRepeats()
    {
        xlSheetClearPrintRepeatsA(handle)
    }

    /// What is going to be printed
    public var printArea: Sheet.CellRange? {
        get {
            var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
            if xlSheetPrintAreaA(handle, &rowFirst, &rowLast, &colFirst, &colLast) == 0  {
                return nil
            }
            return Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                   columns: Int(colFirst)...Int(colLast))
        }
        set {
            guard let range = newValue else {
                return
            }
            xlSheetSetPrintAreaA(handle, Int32(range.rows.lowerBound), Int32(range.rows.upperBound),
                                 Int32(range.columns.lowerBound), Int32(range.columns.upperBound))
        }
    }

    /// Clears the print area
    public func clearPrintArea()
    {
        xlSheetClearPrintAreaA(handle)
    }


    // MARK: - Named Ranges

    public enum NamedRangeSearchScope: Equatable {
        case Sheet(atIndex: Int)
        case Global

        func toRaw() -> Int32
        {
            switch self {
            case let .Sheet(idx):
                return Int32(idx)
            case .Global:
                return Int32(SCOPE_WORKBOOK.rawValue)
            }
        }

        public static func ==(lhs: Sheet.NamedRangeSearchScope, rhs: Sheet.NamedRangeSearchScope) -> Bool
        {
            switch (lhs, rhs) {
            case let (.Sheet(a), .Sheet(b)):
                return a == b
            case (.Global, .Global):
                return true
            default:
                return false
            }
        }
    }

    public struct NamedRange: Equatable {
        public let name: String
        public let cells: Sheet.CellRange
        public let hidden: Bool

        public init(name: String, cells: Sheet.CellRange, hidden: Bool = false)
        {
            self.name = name
            self.cells = cells
            self.hidden = hidden
        }

        public static func ==(lhs: Sheet.NamedRange, rhs: Sheet.NamedRange) -> Bool
        {
            return (lhs.name == rhs.name) && (lhs.cells == rhs.cells) &&
                (lhs.hidden == rhs.hidden)
        }
    }

    /// Returns a named cell range by its name
    public func namedRange(withName name: String, searchScope scope: NamedRangeSearchScope) -> Sheet.NamedRange?
    {
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        var hidden: Int32 = 0
        let status = name.utf8CString.withUnsafeBufferPointer {
            xlSheetGetNamedRangeA(handle, $0.baseAddress, &rowFirst, &rowLast, &colFirst, &colLast, scope.toRaw(), &hidden)
        }
        if status == 0 {
            return nil
        }
        let cells = Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                    columns: Int(colFirst)...Int(colLast))
        return Sheet.NamedRange(name: name, cells: cells, hidden: Bool(hidden == 1))
    }

    /// Adds a named range
    public func add(namedRange range: Sheet.NamedRange, scope: NamedRangeSearchScope) throws
    {
        let status = range.name.utf8CString.withUnsafeBufferPointer {
            xlSheetSetNamedRangeA(handle, $0.baseAddress, Int32(range.cells.rows.lowerBound),
                                  Int32(range.cells.rows.upperBound),
                                  Int32(range.cells.columns.lowerBound), Int32(range.cells.columns.upperBound),
                                  scope.toRaw())
        }
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    // Deletes a named range by its name
    public func delete(namedRange name: String, searchScope scope: NamedRangeSearchScope) throws
    {
        let status = name.utf8CString.withUnsafeBufferPointer {
            xlSheetDelNamedRangeA(handle, $0.baseAddress, scope.toRaw())
        }
        if status == 0 {
            throw SheetError.InternalError(message: parentBook.lastErrorMessage)
        }
    }

    // Number of named ranges in this sheet
    public var numberOfNamedRanges: Int {
        get {
            return Int(xlSheetNamedRangeSizeA(handle))
        }
    }

    /// Returns a named cell range by its index
    public func namedRange(atIndex index: Int) -> Sheet.NamedRange?
    {
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        var hidden: Int32 = 0, scope: Int32 = 0

        let rawName = xlSheetNamedRangeA(handle, Int32(index), &rowFirst, &rowLast, &colFirst, &colLast, &scope, &hidden)

        return rawName.flatMap({ String(utf8String: $0) }).map {
            let cells = Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                        columns: Int(colFirst)...Int(colLast))
            return Sheet.NamedRange(name: $0, cells: cells, hidden: Bool(hidden == 1))
        }
    }


    // MARK: - Tables

    // Returns the number of tables in this sheet
    public var numberOfTables: Int {
        get {
            return Int(xlSheetTableSizeA(handle))
        }
    }

    public struct Table: Equatable {
        public let name: String
        public let cells: Sheet.CellRange
        /// The number of header rows showing at the top of the table. The value of 0 means
        /// that the header row is not shown
        public let headerRowCount: Int
        /// the number of totals rows that shall be shown at the bottom of the table. The value
        /// of 0 means that the totals row is not shown
        public let totalsRowCount: Int

        public static func ==(lhs: Sheet.Table, rhs: Sheet.Table) -> Bool
        {
            return (lhs.name == rhs.name) && (lhs.cells == rhs.cells) && (lhs.headerRowCount == rhs.headerRowCount) && (lhs.totalsRowCount == rhs.totalsRowCount)
        }
    }

    /// Returns a table by its index
    public func table(atIndex index: Int) -> Sheet.Table?
    {
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        var headerRowCount: Int32 = 0, totalsRowCount: Int32 = 0

        let rawName = xlSheetTableA(handle, Int32(index), &rowFirst, &rowLast, &colFirst, &colLast, &headerRowCount, &totalsRowCount)
        return rawName.flatMap({ String(utf8String: $0) }).map {
            let cells = Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                        columns: Int(colFirst)...Int(colLast))
            return Sheet.Table(name: $0, cells: cells,
                               headerRowCount: Int(headerRowCount), totalsRowCount: Int(totalsRowCount))
        }
    }

    // MARK: - Hyperlinks

    /// Returns the number of hyperlinks in the sheet
    public var numberOfHyperlinks: Int {
        get {
            return Int(xlSheetHyperlinkSizeA(handle))
        }
    }

    public struct Hyperlink: Equatable
    {
        public let value: String
        public let occupiedCells: Sheet.CellRange

        public init(value: String, occupiedCells: Sheet.CellRange)
        {
            self.value = value
            self.occupiedCells = occupiedCells
        }

        public static func ==(lhs: Sheet.Hyperlink, rhs: Sheet.Hyperlink) -> Bool
        {
            return (lhs.value == rhs.value) && (lhs.occupiedCells == rhs.occupiedCells)
        }
    }

    /// Returns a hyperlink by its index
    public func hyperlink(atIndex index: Int) -> Sheet.Hyperlink?
    {
        var rowFirst: Int32 = 0, rowLast: Int32 = 0, colFirst: Int32 = 0, colLast: Int32 = 0
        let rawValue = xlSheetHyperlinkA(handle, Int32(index), &rowFirst, &rowLast, &colFirst, &colLast)
        return rawValue.flatMap({ String(utf8String: $0) }).map {
            let cells = Sheet.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                        columns: Int(colFirst)...Int(colLast))
            return Sheet.Hyperlink(value: $0, occupiedCells: cells)
        }
    }

    /// Removes a hyperlink by index
    public func delete(hyperlinkAtIndex index: Int)
    {
        xlSheetDelHyperlinkA(handle, Int32(index))
    }

    /// Adds a new hyperlink
    public func add(hyperlink: Sheet.Hyperlink)
    {
        add(hyperlink: hyperlink.value, forCells: hyperlink.occupiedCells)
    }

    /// Adds a new hyperlink for the given range of cells
    public func add(hyperlink: String, forCells cells: Sheet.CellRange)
    {
        hyperlink.utf8CString.withUnsafeBufferPointer {
            xlSheetAddHyperlinkA(handle, $0.baseAddress, Int32(cells.rows.lowerBound),
                                 Int32(cells.rows.upperBound),
                                 Int32(cells.columns.lowerBound), Int32(cells.columns.upperBound))
        }
    }

    // MARK: - Views

    /// The first visible row of the sheet
    public var firstVisibleRow: Int {
        get {
            var row: Int32 = 0, column: Int32 = 0
            xlSheetGetTopLeftViewA(handle, &row, &column)
            return Int(row)
        }
        set {
            xlSheetSetTopLeftViewA(handle, Int32(newValue), Int32(firstVisibleColumn))
        }
    }
    /// The leftmost visible column of the sheet
    public var firstVisibleColumn: Int {
        get {
            var row: Int32 = 0, column: Int32 = 0
            xlSheetGetTopLeftViewA(handle, &row, &column)
            return Int(column)
        }
        set {
            xlSheetSetTopLeftViewA(handle, Int32(firstVisibleRow), Int32(newValue))
        }
    }

    // MARK: - Cell References

    public struct CellLookup: Equatable {
        public let row: Int
        public let column: Int
        public let relativeRow: Bool
        public let relativeColumn: Bool

        public init(row: Int, column: Int, relativeRow: Bool, relativeColumn: Bool)
        {
            self.row = row
            self.column = column
            self.relativeRow = relativeRow
            self.relativeColumn = relativeColumn
        }

        public static func ==(lhs: Sheet.CellLookup, rhs: Sheet.CellLookup) -> Bool
        {
            return (lhs.row == rhs.row) && (lhs.column == rhs.column) && (lhs.relativeRow == rhs.relativeRow) && (lhs.relativeColumn == rhs.relativeColumn)
        }
    }

    /// Converts a cell reference to a corresonding row and column
    public func cellReferenceToCell(_ addr: String) -> Sheet.CellLookup
    {
        var row: Int32 = 0, col: Int32 = 0, rowRelative: Int32 = 0, colRelative: Int32 = 0
        addr.utf8CString.withUnsafeBufferPointer {
            xlSheetAddrToRowColA(handle, $0.baseAddress, &row, &col, &rowRelative, &colRelative)
        }
        return Sheet.CellLookup(row: Int(row), column: Int(col),
                                relativeRow: Bool(rowRelative == 1),
                                relativeColumn: Bool(colRelative == 1))
    }

    /// Converts row and column to a corresponding cell reference
    public func cellToCellReference(_ cell: CellLookup) -> String?
    {
        let rawReference = xlSheetRowColToAddrA(handle, Int32(cell.row), Int32(cell.column),
                                                Int32(cell.relativeRow ? 1 : 0),
                                                Int32(cell.relativeColumn ? 1 : 0))
        return rawReference.flatMap({ String(utf8String: $0)})
    }

    // MARK: - Tab Colors

    public typealias SheetTabColor = FontColor

    /// Sets the color for the sheet's tab
    public func set(sheetTabColor color: SheetTabColor)
    {
        xlSheetSetTabColorA(handle, color.toRaw())
    }

    /// Sets the color for the sheet's tab
    public func set(sheetTabColor color: NSColor)
    {
        let red = Int32(color.redComponent * 255)
        let green = Int32(color.greenComponent * 255)
        let blue = Int32(color.blueComponent * 255)
        xlSheetSetTabRgbColorA(handle, red, green, blue)
    }

    // MARK: - Misc

    public enum IgnoredError {
        /// Ignore errors when cells contain formulas that result in an error
        case Evaluation
        /// Ignore errors when formulas refer to empty cells
        case EmptyCellReference
        /// Ignore errors when numbers are formatted as text or are preceded by an apostrophe
        case NumberAsText
        /// Ignore errors when formulas omit certain cells in a region
        case InconsistentRange
        /// Ignore errors when a formula in a region of your worksheet differs from other
        /// formulas in the same region
        case InconsistentFormula
        /// Ignore errors when formulas contain text formatted cells with years represented
        /// as 2 digits
        case TwoDigitsTextYear
        /// Ignore errors when unlocked cells contain formulas.
        case UnlockedFormula
        /// Ignore errors when a cell's value in a Table does not comply with the
        /// Data Validation rules specified.
        case DataValidation
    }

    /// Adds the ignored error for specified range.
    /// It allows to hide green triangles on left sides of cells. For example, if a cell is
    /// formatted as text but contains a numeric value, this is considered to be a potential error
    /// because the number won't be treated as a number, for example, in calculations.
    public func ignore(errors: [Sheet.IgnoredError], forCells cells: Sheet.CellRange)
    {
        let errorFlags = errors.reduce(0) { $0 | $1.toRaw() }
        xlSheetAddIgnoredErrorA(handle, Int32(cells.rows.lowerBound), Int32(cells.rows.upperBound),
                                Int32(cells.columns.lowerBound), Int32(cells.columns.upperBound),
                                errorFlags)
    }
}

// MARK: - Bridging -

internal extension SheetType {

    static func from(rawValue raw: Int32) -> SheetType
    {
        switch raw {
        case Int32(SHEETTYPE_SHEET.rawValue): return .Standart
        case Int32(SHEETTYPE_CHART.rawValue): return .Chart
        default:
            return .Unknown
        }
    }
}

fileprivate extension Sheet.EnhancedProtection {

    func toRaw() -> Int32
    {
        switch self {
        case .Default:
            return Int32(PROT_DEFAULT.rawValue)
        case .All:
            return Int32(PROT_ALL.rawValue)
        case .Objects:
            return Int32(PROT_OBJECTS.rawValue)
        case .Scenarios:
            return Int32(PROT_SCENARIOS.rawValue)
        case .FormattingCells:
            return Int32(PROT_FORMAT_CELLS.rawValue)
        case .FormattingColumns:
            return Int32(PROT_FORMAT_COLUMNS.rawValue)
        case .FormattingRows:
            return Int32(PROT_FORMAT_ROWS.rawValue)
        case .InsertingColumns:
            return Int32(PROT_INSERT_COLUMNS.rawValue)
        case .InsertingRows:
            return Int32(PROT_INSERT_ROWS.rawValue)
        case .InsertingHyperlinks:
            return Int32(PROT_INSERT_HYPERLINKS.rawValue)
        case .DeletingColumns:
            return Int32(PROT_DELETE_COLUMNS.rawValue)
        case .DeletingRows:
            return Int32(PROT_DELETE_ROWS.rawValue)
        case .SelectingLockedCells:
            return Int32(PROT_SEL_LOCKED_CELLS.rawValue)
        case .Sorting:
            return Int32(PROT_SORT.rawValue)
        case .Autofilters:
            return Int32(PROT_AUTOFILTER.rawValue)
        case .PivotTables:
            return Int32(PROT_PIVOTTABLES.rawValue)
        case .SelectingUnlockedCells:
            return Int32(PROT_SEL_UNLOCKED_CELLS.rawValue)
        }
    }
}


fileprivate extension Sheet.CellType {

    static func errorType() -> Int32
    {
        return Int32(CELLTYPE_ERROR.rawValue)
    }

    static func from(rawValue raw: Int32) -> Sheet.CellType
    {
        switch raw {
        case Int32(CELLTYPE_EMPTY.rawValue): return .Empty
        case Int32(CELLTYPE_NUMBER.rawValue): return .Number
        case Int32(CELLTYPE_STRING.rawValue): return .String
        case Int32(CELLTYPE_BOOLEAN.rawValue): return .Boolean
        case Int32(CELLTYPE_BLANK.rawValue): return .Blank
        default:
            return .Blank
        }
    }
}

fileprivate extension Sheet.IgnoredError {

    func toRaw() -> Int32
    {
        switch self {
        case .Evaluation:
            return Int32(IERR_EVAL_ERROR.rawValue)
        case .EmptyCellReference:
            return Int32(IERR_EMPTY_CELLREF.rawValue)
        case .NumberAsText:
            return Int32(IERR_NUMBER_STORED_AS_TEXT.rawValue)
        case .InconsistentRange:
            return Int32(IERR_INCONSIST_RANGE.rawValue)
        case .InconsistentFormula:
            return Int32(IERR_INCONSIST_FMLA.rawValue)
        case .TwoDigitsTextYear:
            return Int32(IERR_TWODIG_TEXTYEAR.rawValue)
        case .UnlockedFormula:
            return Int32(IERR_UNLOCK_FMLA.rawValue)
        case .DataValidation:
            return Int32(IERR_DATA_VALIDATION.rawValue)
        }
    }
}

fileprivate extension Sheet.ColumnWidth {

    func toRaw() -> Double
    {
        switch self {
        case .Auto: return -1
        case let .Exactly(w): return w
        }
    }
}

fileprivate extension Sheet.HiddenStatus {

    func toRaw() -> Int32
    {
        switch self {
        case .Visible: return Int32(SHEETSTATE_VISIBLE.rawValue)
        case .Hidden: return Int32(SHEETSTATE_HIDDEN.rawValue)
        case .VeryHidden: return Int32(SHEETSTATE_VISIBLE.rawValue)
        }
    }

    static func from(raw: Int32) -> Sheet.HiddenStatus
    {
        switch raw {
        case Int32(SHEETSTATE_VISIBLE.rawValue): return .Visible
        case Int32(SHEETSTATE_HIDDEN.rawValue): return .Hidden
        case Int32(SHEETSTATE_VISIBLE.rawValue): return .VeryHidden
        default:
            fatalError("Invalid raw value for Sheet.HiddenStatus: \(raw)")
        }
    }
}


fileprivate extension Sheet.CalculationError {

    static func from(raw: Int32) -> Sheet.CalculationError
    {
        switch raw {
        case Int32(ERRORTYPE_NULL.rawValue):
            return .Null
        case Int32(ERRORTYPE_DIV_0.rawValue):
            return .DivisionByZero
        case Int32(ERRORTYPE_VALUE.rawValue):
            return .Value
        case Int32(ERRORTYPE_REF.rawValue):
            return .Reference
        case Int32(ERRORTYPE_NAME.rawValue):
            return .Name
        case Int32(ERRORTYPE_NUM.rawValue):
            return .Number
        case Int32(ERRORTYPE_NA.rawValue):
            return .NA
        case Int32(ERRORTYPE_NOERROR.rawValue):
            return .NoError
        default:
            fatalError("Unexpected raw value for Sheet.CalculationError: \(raw)")
        }
    }

    func toRaw() -> Int32
    {
        switch self {
        case .Null:
            return Int32(ERRORTYPE_NULL.rawValue)
        case .DivisionByZero:
            return Int32(ERRORTYPE_DIV_0.rawValue)
        case .Value:
            return Int32(ERRORTYPE_VALUE.rawValue)
        case .Reference:
            return Int32(ERRORTYPE_REF.rawValue)
        case .Name:
            return Int32(ERRORTYPE_NAME.rawValue)
        case .Number:
            return Int32(ERRORTYPE_NUM.rawValue)
        case .NA:
            return Int32(ERRORTYPE_NA.rawValue)
        case .NoError:
            return Int32(ERRORTYPE_NOERROR.rawValue)
        }
    }
}

fileprivate extension Sheet.PaperSize {

    func toRaw() -> Int32
    {
        switch self {
        case .Default:
            return Int32(PAPER_DEFAULT.rawValue)
        case .Letter:
            return Int32(PAPER_LETTER.rawValue)
        case .LetterSmall:
            return Int32(PAPER_LETTERSMALL.rawValue)
        case .Tabloid:
            return Int32(PAPER_TABLOID.rawValue)
        case .Ledger:
            return Int32(PAPER_LEDGER.rawValue)
        case .Legal:
            return Int32(PAPER_LEGAL.rawValue)
        case .Statement:
            return Int32(PAPER_STATEMENT.rawValue)
        case .Executive:
            return Int32(PAPER_EXECUTIVE.rawValue)
        case .A3:
            return Int32(PAPER_A3.rawValue)
        case .A4:
            return Int32(PAPER_A4.rawValue)
        case .A4Small:
            return Int32(PAPER_A4SMALL.rawValue)
        case .A5:
            return Int32(PAPER_A5.rawValue)
        case .B4:
            return Int32(PAPER_B4.rawValue)
        case .B5:
            return Int32(PAPER_B5.rawValue)
        case .Folio:
            return Int32(PAPER_FOLIO.rawValue)
        case .Quatro:
            return Int32(PAPER_QUATRO.rawValue)
        case .Inches10x14:
            return Int32(PAPER_10x14.rawValue)
        case .Inches10x17:
            return Int32(PAPER_10x17.rawValue)
        case .Note:
            return Int32(PAPER_NOTE.rawValue)
        case .Envelope9:
            return Int32(PAPER_ENVELOPE_9.rawValue)
        case .Envelope10:
            return Int32(PAPER_ENVELOPE_10.rawValue)
        case .Envelope11:
            return Int32(PAPER_ENVELOPE_11.rawValue)
        case .Envelope12:
            return Int32(PAPER_ENVELOPE_12.rawValue)
        case .Envelope14:
            return Int32(PAPER_ENVELOPE_14.rawValue)
        case .CSize:
            return Int32(PAPER_C_SIZE.rawValue)
        case .Dsize:
            return Int32(PAPER_D_SIZE.rawValue)
        case .ESize:
            return Int32(PAPER_E_SIZE.rawValue)
        case .Envelope:
            return Int32(PAPER_ENVELOPE.rawValue)
        case .EnvelopeDL:
            return Int32(PAPER_ENVELOPE_DL.rawValue)
        case .EnvelopeC3:
            return Int32(PAPER_ENVELOPE_C3.rawValue)
        case .EnvelopeC4:
            return Int32(PAPER_ENVELOPE_C4.rawValue)
        case .EnvelopeC5:
            return Int32(PAPER_ENVELOPE_C5.rawValue)
        case .EnvelopeC6:
            return Int32(PAPER_ENVELOPE_C6.rawValue)
        case .EnvelopeC65:
            return Int32(PAPER_ENVELOPE_C65.rawValue)
        case .EnvelopeB4:
            return Int32(PAPER_ENVELOPE_B4.rawValue)
        case .EnvelopeB5:
            return Int32(PAPER_ENVELOPE_B5.rawValue)
        case .EnvelopeB6:
            return Int32(PAPER_ENVELOPE_B6.rawValue)
        case .EnvelopeMonarch:
            return Int32(PAPER_ENVELOPE_MONARCH.rawValue)
        case .EnvelopeUS:
            return Int32(PAPER_US_ENVELOPE.rawValue)
        case .Fanfold:
            return Int32(PAPER_FANFOLD.rawValue)
        case .GermanStandartFanfold:
            return Int32(PAPER_GERMAN_STD_FANFOLD.rawValue)
        case .GermanLegalFanfold:
            return Int32(PAPER_GERMAN_LEGAL_FANFOLD.rawValue)
        }
    }

    static func from(raw: Int32) -> Sheet.PaperSize
    {
        switch raw {
        case Int32(PAPER_DEFAULT.rawValue):
            return .Default
        case Int32(PAPER_LETTER.rawValue):
            return .Letter
        case Int32(PAPER_LETTERSMALL.rawValue):
            return .LetterSmall
        case Int32(PAPER_TABLOID.rawValue):
            return .Tabloid
        case Int32(PAPER_LEDGER.rawValue):
            return .Ledger
        case Int32(PAPER_LEGAL.rawValue):
            return .Legal
        case Int32(PAPER_STATEMENT.rawValue):
            return .Statement
        case Int32(PAPER_EXECUTIVE.rawValue):
            return .Executive
        case Int32(PAPER_A3.rawValue):
            return .A3
        case Int32(PAPER_A4.rawValue):
            return .A4
        case Int32(PAPER_A4SMALL.rawValue):
            return .A4Small
        case Int32(PAPER_A5.rawValue):
            return .A5
        case Int32(PAPER_B4.rawValue):
            return .B4
        case Int32(PAPER_B5.rawValue):
            return .B5
        case Int32(PAPER_FOLIO.rawValue):
            return .Folio
        case Int32(PAPER_QUATRO.rawValue):
            return .Quatro
        case Int32(PAPER_10x14.rawValue):
            return .Inches10x14
        case Int32(PAPER_10x17.rawValue):
            return .Inches10x17
        case Int32(PAPER_NOTE.rawValue):
            return .Note
        case Int32(PAPER_ENVELOPE_9.rawValue):
            return .Envelope9
        case Int32(PAPER_ENVELOPE_10.rawValue):
            return .Envelope10
        case Int32(PAPER_ENVELOPE_11.rawValue):
            return .Envelope11
        case Int32(PAPER_ENVELOPE_12.rawValue):
            return .Envelope12
        case Int32(PAPER_ENVELOPE_14.rawValue):
            return .Envelope14
        case Int32(PAPER_C_SIZE.rawValue):
            return .CSize
        case Int32(PAPER_D_SIZE.rawValue):
            return .Dsize
        case Int32(PAPER_E_SIZE.rawValue):
            return .ESize
        case Int32(PAPER_ENVELOPE.rawValue):
            return .Envelope
        case Int32(PAPER_ENVELOPE_DL.rawValue):
            return .EnvelopeDL
        case Int32(PAPER_ENVELOPE_C3.rawValue):
            return .EnvelopeC3
        case Int32(PAPER_ENVELOPE_C4.rawValue):
            return .EnvelopeC4
        case Int32(PAPER_ENVELOPE_C5.rawValue):
            return .EnvelopeC5
        case Int32(PAPER_ENVELOPE_C6.rawValue):
            return .EnvelopeC6
        case Int32(PAPER_ENVELOPE_C65.rawValue):
            return .EnvelopeC65
        case Int32(PAPER_ENVELOPE_B4.rawValue):
            return .EnvelopeB4
        case Int32(PAPER_ENVELOPE_B5.rawValue):
            return .EnvelopeB5
        case Int32(PAPER_ENVELOPE_B6.rawValue):
            return .EnvelopeB6
        case Int32(PAPER_ENVELOPE_MONARCH.rawValue):
            return .EnvelopeMonarch
        case Int32(PAPER_US_ENVELOPE.rawValue):
            return .EnvelopeUS
        case Int32(PAPER_FANFOLD.rawValue):
            return .Fanfold
        case Int32(PAPER_GERMAN_STD_FANFOLD.rawValue):
            return .GermanStandartFanfold
        case Int32(PAPER_GERMAN_LEGAL_FANFOLD.rawValue):
            return .GermanLegalFanfold
        default:
            fatalError("Invalid raw value for Sheet.PaperSize: \(raw)")
        }
    }
}
