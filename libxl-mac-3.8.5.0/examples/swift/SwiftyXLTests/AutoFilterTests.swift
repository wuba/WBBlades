//
//  AutoFilterTests.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 20/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import XCTest
import SwiftyXL

class AutoFilterTests: SwiftyXLTestCase {

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



}
