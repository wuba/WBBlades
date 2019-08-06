//
//  FormatTests.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 19/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import XCTest
import SwiftyXL

class FormatTests: SwiftyXLTestCase {

    var book: Book! = nil
    var format: Format! = nil

    override func setUp() {
        super.setUp()
        book = Book()
        format = try! book.add(formatByCopying: nil)
    }

    override func tearDown() {
        format = nil
        book = nil
        super.tearDown()
    }

    func testFetchingLocked()
    {
        XCTAssertEqual(format.locked, true)
    }

    func testSettingLocked()
    {
        // when
        format.locked = false
        // then
        XCTAssertEqual(format.locked, false)
    }

    func testFetchingHidden()
    {
        XCTAssertEqual(format.hidden, false)
    }

    func testSettingHidden()
    {
        // when
        format.hidden = true
        // then
        XCTAssertEqual(format.hidden, true)
    }

    func testFetchingFont()
    {
        XCTAssertNotNil(format.font)
    }

    func testSettingFont()
    {
        // when
        let font = try! book!.add(fontByCopying: nil)
        format.font = font
        // then
        XCTAssertEqual(format.font?.name, font.name)
        XCTAssertEqual(format.font?.size, font.size)
    }

    func testFetchingNumberFormat()
    {
        XCTAssertEqual(format.numberFormat, NumberFormat.General)
    }

    func testSettingNumberFormat()
    {
        // given
        let value: NumberFormat = .CustomDate(format: .DayMonth)
        // when
        format.numberFormat = value
        // then
        XCTAssertEqual(format.numberFormat, value)
    }

    func testFetchingHorizontalAlignment()
    {
        XCTAssertEqual(format.horizontalAlignment, .General)
    }

    func testSettingHorizontalAlignment()
    {
        // given
        let alignment: FormatHorizontalAlignment = .Justify
        // when
        format.horizontalAlignment = alignment
        // then
        XCTAssertEqual(format.horizontalAlignment, alignment)
    }

    func testFetchingVerticalAlignment()
    {
        XCTAssertEqual(format.verticalAlignment, .Bottom)
    }

    func testSettingVerticalAlignment()
    {
        // given
        let alignment: FormatVerticalAlignment = .Distributed
        // when
        format.verticalAlignment = alignment
        // then
        XCTAssertEqual(format.verticalAlignment, alignment)
    }

    func testFetchingWrapCellText()
    {
        XCTAssertEqual(format.wrapCellText, false)
    }

    func testSettingWrapCellText()
    {
        // when
        format.wrapCellText = true
        // then
        XCTAssertEqual(format.wrapCellText, true)
    }

    func testFetchingTextRotation()
    {
        XCTAssertEqual(format.textRotation, .Counterclockwise(degrees: 0))
    }

    func testSettingTextRotation()
    {
        // given
        let a: FormatTextRotation = .Clockwise(degrees: 41)
        let b: FormatTextRotation = .Vertical
        // when
        format.textRotation = a
        // then
        XCTAssertEqual(format.textRotation, a)
        // when
        format.textRotation = b
        // then
        XCTAssertEqual(format.textRotation, b)
    }

    func testFetchingTextIndentation()
    {
        XCTAssertEqual(format.textIndentationLevel, 0)
    }

    func testSettingTextIndentation()
    {
        // given
        let a = 6
        let b = Format.maxTextIndentationLevel * 10
        // when
        format.textIndentationLevel = a
        // then
        XCTAssertEqual(format.textIndentationLevel, a)
        // when
        format.textIndentationLevel = b
        // then
        XCTAssertEqual(format.textIndentationLevel, Format.maxTextIndentationLevel)
    }

    func testFetchingShrinkToFit()
    {
        XCTAssertEqual(format.shrinkToFit, false)
    }

    func testSettingShrinkToFit()
    {
        // when
        format.shrinkToFit = true
        // then
        XCTAssertEqual(format.shrinkToFit, true)
    }

    func testFetchingBorderStyle()
    {
        XCTAssertEqual(format.style(of: .LeftBorder), .None)
        XCTAssertEqual(format.style(of: .TopBorder), .None)
    }

    func testSettingBorderStyle()
    {
        // given
        let leftBorderStyle: FormatBorderStyle = .Thin
        let topBorderStyle: FormatBorderStyle = .DashDotDot
        // when
        format.set(style: leftBorderStyle, for: .LeftBorder)
        format.set(style: topBorderStyle, for: .TopBorder)
        // then
        XCTAssertEqual(format.style(of: .LeftBorder), leftBorderStyle)
        XCTAssertEqual(format.style(of: .TopBorder), topBorderStyle)
        XCTAssertEqual(format.style(of: .BottomBorder), .None)
    }

    func testFecthingBorderColor()
    {
        XCTAssertEqual(format.color(of: .RightBorder), .DefaultForeground)
    }

    func testSettingBorderColor()
    {
        // given
        let pink: FormatBorderColor = .Pink
        let aqua: FormatBorderColor = .Aqua
        // when
        format.set(color: pink, for: .RightBorder)
        format.set(color: aqua, for: .BottomBorder)
        // then
        XCTAssertEqual(format.color(of: .RightBorder), pink)
        XCTAssertEqual(format.color(of: .BottomBorder), aqua)
    }

    func testFetchingDiagonalBorder()
    {
        XCTAssertEqual(format.diagonalBorder, .None)
    }

    func testSettingDiagonalBorder()
    {
        // given
        let downDashedPink: FormatDiagonalBorderType = .Down(style: .Dashed, color: .Pink)
        let bothVioletHair: FormatDiagonalBorderType = .Both(style: .Hair, color: .Violet)
        // when
        format.diagonalBorder = downDashedPink
        // then
        XCTAssertEqual(format.diagonalBorder, downDashedPink)
        // when
        format.diagonalBorder = bothVioletHair
        // then
        XCTAssertEqual(format.diagonalBorder, bothVioletHair)
    }

    func testFetchingFillPattern()
    {
        XCTAssertEqual(format.fillPattern, .None)
    }

    func testSettingFillPattern()
    {
        // given
        let diagonalStripesYellowOnRed: FormatFillPattern = .DiagonalStripes(foreground: .Yellow, background: .Red)
        let thinHorizontalCrosshatchTanOnGold: FormatFillPattern = .ThinHorizontalCrosshatch(foreground: .Tan, background: .Gold)
        // when
        format.fillPattern = diagonalStripesYellowOnRed
        // then
        XCTAssertEqual(format.fillPattern, diagonalStripesYellowOnRed)
        // when
        format.fillPattern = thinHorizontalCrosshatchTanOnGold
        // then
        XCTAssertEqual(format.fillPattern, thinHorizontalCrosshatchTanOnGold)
    }
}
