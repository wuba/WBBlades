//
//  AutoFilter.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 20/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public class AutoFilter {

    let handle: AutoFilterHandle

    init(handle: AutoFilterHandle)
    {
        self.handle = handle
    }

    public struct CellRange {
        public let rows: CountableClosedRange<Int>
        public let columns: CountableClosedRange<Int>

        public init(rows: CountableClosedRange<Int>, columns: CountableClosedRange<Int>)
        {
            self.rows = rows
            self.columns = columns
        }
    }

    /// A range of cells affected by this auto filter. This includes the header cells as well.
    public var cellRange: AutoFilter.CellRange? {
        get {
            var rowFirst: Int32 = 0, rowLast: Int32 = 0, columnFirst: Int32 = 0, columnLast: Int32 = 0
            let status = xlAutoFilterGetRefA(handle, &rowFirst, &rowLast, &columnFirst, &columnLast)
            guard status != 0 else {
                return nil
            }
            return AutoFilter.CellRange(rows: Int(rowFirst)...Int(rowLast),
                                       columns: Int(columnFirst)...Int(columnLast))
        }
        set {
            guard let range = newValue else {
                return
            }
            xlAutoFilterSetRefA(handle, Int32(range.rows.lowerBound), Int32(range.rows.upperBound),
                                Int32(range.columns.lowerBound), Int32(range.columns.upperBound))
        }
    }

    public typealias SortRange = AutoFilter.CellRange

    /// A range of cells affected by sort operations
    public var sortRange: AutoFilter.SortRange? {
        get {
            var rowFirst: Int32 = 0, rowLast: Int32 = 0, columnFirst: Int32 = 0, columnLast: Int32 = 0
            let status = xlAutoFilterGetSortRangeA(handle, &rowFirst, &rowLast, &columnFirst, &columnLast)
            guard status != 0 else {
                return nil
            }
            return AutoFilter.SortRange(rows: Int(rowFirst)...Int(rowLast),
                                       columns: Int(columnFirst)...Int(columnLast))
        }
    }

    public struct SortType {
        public let column: Int
        public let ascending: Bool

        public init(column: Int, ascending: Bool)
        {
            self.column = column
            self.ascending = ascending
        }
    }

    /// A type of sort operation to apply to this auto filter
    public var sortType: AutoFilter.SortType? {
        get {
            var columnIndex: Int32 = 0, descending: Int32 = 0
            let status = xlAutoFilterGetSortA(handle, &columnIndex, &descending)
            guard status != 0 else {
                return nil
            }
            return AutoFilter.SortType(column: Int(columnIndex), ascending: Bool(descending == 0))
        }
        set {
            guard let type = newValue else {
                return
            }
            xlAutoFilterSetSortA(handle, Int32(type.column), Int32(!type.ascending ? 1 : 0))
        }
    }

    /// Returns the AutoFilter column by zero-based index. Creates one if it doesn't exist yet
    public func column(atIndex idx: Int) -> FilterColumn
    {
        // This should never be nil
        let columnHandle = xlAutoFilterColumnA(handle, Int32(idx))!
        return FilterColumn(handle: columnHandle)
    }

    /// Returns the specified AutoFilter column which have a filter information by index
    public func filterColumn(atIndex idx: Int) -> FilterColumn?
    {
        let columnHandle = xlAutoFilterColumnByIndexA(handle, Int32(idx))
        return columnHandle.map { FilterColumn(handle: $0)}
    }

    /// Returns the number of specified AutoFilter columns which have a filter information
    public var columnSize: Int {
        get {
            return Int(xlAutoFilterColumnSizeA(handle))
        }
    }

}
