//
//  FontTests.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 19/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import XCTest
import SwiftyXL

class FontTests: SwiftyXLTestCase {

    var book: Book? = nil
    var font: Font? = nil

    override func setUp() {
        super.setUp()
        book = Book()
        font = try! book!.add(fontByCopying: nil)
    }
    
    override func tearDown() {
        font = nil
        book = nil
        super.tearDown()
    }

    func testFetchingName()
    {
        // when
        let defaultName = font!.name
        // then
        XCTAssertGreaterThan(defaultName.lengthOfBytes(using: .utf8), 0)
    }

    func testSettingName()
    {
        // given
        let name = "Times New Roman"
        // when
        font!.name = name
        // then
        XCTAssertEqual(font!.name, name)
    }

    func testFetchingSize()
    {
        XCTAssertGreaterThan(font!.size, 0)
    }

    func testSettingSize()
    {
        // given
        let size = 19
        // when
        font!.size = size
        // then
        XCTAssertEqual(font!.size, size)
    }

    func testFetchingBold()
    {
        XCTAssertEqual(font!.bold, false)
    }

    func testSettingBold()
    {
        // when
        font!.bold = true
        // then
        XCTAssertEqual(font!.bold, true)
    }

    func testFetchingItalic()
    {
        XCTAssertEqual(font!.italic, false)
    }

    func testSettingItalic()
    {
        // when
        font!.italic = true
        // then
        XCTAssertEqual(font!.italic, true)
    }

    func testFetchingStrikeOut()
    {
        XCTAssertEqual(font!.strikeOut, false)
    }

    func testSettingStrikeOut()
    {
        // when
        font!.strikeOut = true
        // then
        XCTAssertEqual(font!.strikeOut, true)
    }

    func testFetchingUnderline()
    {
        XCTAssertEqual(font!.underline, .None)
    }

    func testSettingUnderline()
    {
        // given
        let style: FontUnderlineStyle = .Double
        // when
        font!.underline = style
        // then
        XCTAssertEqual(font!.underline, style)
    }

    func testSettingColor()
    {
        // given
        let color: FontColor = .Teal
        // when
        font!.color = color
        // then
        XCTAssertEqual(font!.color, color)
    }

    func testFetchingBaseline()
    {
        XCTAssertEqual(font!.baseline, .Normal)
    }

    func testSettingBaseline()
    {
        // given
        let baseline: FontBaseline = .Subscript
        // when
        font!.baseline = baseline
        // then
        XCTAssertEqual(font!.baseline, baseline)
    }
}
