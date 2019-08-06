//
//  FilterColumn.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 20/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public struct Filter: Equatable {
    public let criteria: Criteria
    public let operand: String

    public init(criteria: Criteria, operand: String)
    {
        self.criteria = criteria
        self.operand = operand
    }

    public static func ==(lhs: Filter, rhs: Filter) -> Bool
    {
        return (lhs.criteria == rhs.criteria) && (lhs.operand == rhs.operand)
    }

    public enum Criteria {
        case Equal
        case GreaterThan
        case GreaterThanOrEqual
        case LessThan
        case LessThanOrEqual
        case NotEqual
    }
}

public struct CompoundFilter {
    public let first: Filter
    public let second: Filter?
    public let type: CompoundFilter.Relationship

    public init(first: Filter, second: Filter?, type: CompoundFilter.Relationship)
    {
        self.first = first
        self.second = second
        self.type = type
    }

    public static func ==(lhs: CompoundFilter, rhs: CompoundFilter) -> Bool
    {
        return (lhs.first == rhs.first) && (lhs.second == rhs.second) && (lhs.type == rhs.type)
    }

    public enum Relationship: Int32 {
        case Or = 0
        case And = 1
    }
}

public class FilterColumn {

    let handle: FilterColumnHandle

    init(handle: AutoFilterHandle)
    {
        self.handle = handle
    }

    /// Returns a zero-based index of this AutoFilter column
    public var index: Int {
        get {
            return Int(xlFilterColumnIndexA(handle))
        }
    }

    public enum FilterType {
        case None
        case Value
        case Top10
        case Custom
        case Dynamic
        case Color
        case Icon
        case Extensions
    }

    /// Returns a filter type of this AutoFilter column
    public var filterType: FilterColumn.FilterType {
        get {
            return FilterColumn.FilterType.from(raw: xlFilterColumnFilterTypeA(handle))
        }
    }

    /// Returns the total number of filter values
    public var numberOfFilters: Int {
        get {
            return Int(xlFilterColumnFilterSizeA(handle))
        }
    }

    /// Returns a filter value by its index
    public func filter(atIndex idx: Int) -> String?
    {
        let raw: UnsafePointer<Int8>? = xlFilterColumnFilterA(handle, Int32(idx))
        return raw.map { String(cString: $0)}
    }

    /// Adds a new filter value
    public func add(filter: String)
    {
        filter.utf8CString.withUnsafeBufferPointer {
            xlFilterColumnAddFilterA(handle, $0.baseAddress)
        }
    }

    public struct TopResults: Equatable {
        public let items: Double
        public let kind: Position
        public let usePercent: Bool

        public init(items: Double, kind: Position, usePercent: Bool)
        {
            self.items = items
            self.kind = kind
            self.usePercent = usePercent
        }

        public static func ==(lhs: FilterColumn.TopResults, rhs: FilterColumn.TopResults) -> Bool
        {
            return (lhs.items == rhs.items) && (lhs.kind == rhs.kind) && (lhs.usePercent == rhs.usePercent)
        }

        public enum Position: Int32 {
            case Top = 1
            case Bottom = 0
        }
    }

    /// The number of top (botton) items
    var top10: FilterColumn.TopResults? {
        get {
            var number: Double = 0, top: Int32 = 0, percent: Int32 = 0
            let status = xlFilterColumnGetTop10A(handle, &number, &top, &percent)
            guard status != 0 else {
                return nil
            }
            let kind = FilterColumn.TopResults.Position(rawValue: top)!
            return FilterColumn.TopResults(items: number, kind: kind, usePercent: Bool(percent == 1))
        }
        set {
            guard let top = newValue else {
                return
            }
            xlFilterColumnSetTop10A(handle, top.items, top.kind.rawValue, Int32(top.usePercent ? 1 : 0))
        }
    }

    /// A custom filter criteria
    var customFilter: CompoundFilter? {
        get {
            var op1: Int32 = 0, op2: Int32 = 0, andOp: Int32 = 0
            var v1: UnsafePointer<Int8>?, v2: UnsafePointer<Int8>?
            let status = xlFilterColumnGetCustomFilterA(handle, &op1, &v1, &op2, &v2, &andOp)

            guard let actualV1 = v1, status != 0 else {
                return nil
            }
            let firstFilter = Filter(criteria: Filter.Criteria.from(raw: op1),
                                     operand: String(cString: actualV1))
            let secondFilter = v2.map {
                Filter(criteria: Filter.Criteria.from(raw: op2), operand: String(cString: $0))
            }
            return CompoundFilter(first: firstFilter, second: secondFilter, type: andOp == 1 ? .And : .Or)
        }

        set {
            // Fetch the first filter and the compound type
            guard let first = newValue?.first, let type = newValue?.type else {
                return
            }
            // When we don't have a second filter, just apply the first one and call it a day
            guard let second = newValue?.second else {
                first.operand.utf8CString.withUnsafeBufferPointer {
                    xlFilterColumnSetCustomFilterA(handle, first.criteria.toRaw(), $0.baseAddress)
                }
                return
            }
            // Otherwise save both filters
            first.operand.utf8CString.withUnsafeBufferPointer { firstBuffer in
                second.operand.utf8CString.withUnsafeBufferPointer { secondBuffer in
                    xlFilterColumnSetCustomFilterExA(handle, first.criteria.toRaw(), firstBuffer.baseAddress,
                                                     second.criteria.toRaw(), secondBuffer.baseAddress, type.rawValue)
                }
            }
        }
    }

    /// Clears the filter criteria
    func clear()
    {
        xlFilterColumnClearA(handle)
    }

}

fileprivate extension Filter.Criteria {

    static func from(raw: Int32) -> Filter.Criteria
    {
        switch raw {
        case Int32(OPERATOR_EQUAL.rawValue):
            return .Equal
        case Int32(OPERATOR_GREATER_THAN.rawValue):
            return .GreaterThan
        case Int32(OPERATOR_GREATER_THAN_OR_EQUAL.rawValue):
            return .GreaterThanOrEqual
        case Int32(OPERATOR_LESS_THAN.rawValue):
            return .LessThan
        case Int32(OPERATOR_LESS_THAN_OR_EQUAL.rawValue):
            return .LessThanOrEqual
        case Int32(OPERATOR_NOT_EQUAL.rawValue):
            return .NotEqual
        default:
            fatalError("Invalid Filter.Criteria raw value")
        }
    }

    func toRaw() -> Int32
    {
        switch self {
        case .Equal:
            return Int32(OPERATOR_EQUAL.rawValue)
        case .GreaterThan:
            return Int32(OPERATOR_GREATER_THAN.rawValue)
        case .GreaterThanOrEqual:
            return Int32(OPERATOR_GREATER_THAN_OR_EQUAL.rawValue)
        case .LessThan:
            return Int32(OPERATOR_LESS_THAN.rawValue)
        case .LessThanOrEqual:
            return Int32(OPERATOR_LESS_THAN_OR_EQUAL.rawValue)
        case .NotEqual:
            return Int32(OPERATOR_NOT_EQUAL.rawValue)
        }
    }
}

fileprivate extension FilterColumn.FilterType {

    static func from(raw: Int32) -> FilterColumn.FilterType
    {
        switch raw {
        case Int32(FILTER_NOT_SET.rawValue):
            return .None
        case Int32(FILTER_VALUE.rawValue):
            return .Value
        case Int32(FILTER_TOP10.rawValue):
            return .Top10
        case Int32(FILTER_CUSTOM.rawValue):
            return .Custom
        case Int32(FILTER_DYNAMIC.rawValue):
            return .Dynamic
        case Int32(FILTER_COLOR.rawValue):
            return .Color
        case Int32(FILTER_ICON.rawValue):
            return .Icon
        case Int32(FILTER_EXT.rawValue):
            return .Extensions
        default:
            return .None
        }

    }
}
