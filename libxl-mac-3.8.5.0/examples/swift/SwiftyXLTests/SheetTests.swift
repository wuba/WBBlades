//
//  SheetTests.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 18/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import XCTest
import SwiftyXL

class SheetTests: SwiftyXLTestCase {

    // MARK: - State

    var book: Book! = nil
    var sheet: Sheet! = nil
    let defaultSheetName = "the sheet"

    // MARK: - Misc

    override func setUp()
    {
        super.setUp()
        book = Book()
        sheet = try! book!.add(sheetWithName: defaultSheetName)
    }

    override func tearDown() {
        sheet = nil
        book = nil
        super.tearDown()
    }

    func testFetchingCellType()
    {
        // given
        let row = 13, column = 37 // this cell doesn't exist so it should be empty
        // when
        let type = try? sheet.type(forCellAtRow: row, column: column)
        // then
        XCTAssertNotNil(type)
        XCTAssertEqual(type, .Empty)
    }

//    func testContainsFormula()
//    {
//        XCTFail("not implemented")
//    }

    func testReadingComments()
    {
        // XXX: comments only work in binary books (xls)
        book = nil
        book = Book(format: .Binary)
        sheet = try! book.add(sheetWithName: "whatever")
        // given
        let comment = "hi there"
        let row = 0, column = 0
        let commentSize = NSMakeSize(200, 100)
        // when
        sheet.write(comment: comment, forCellAtRow: row, column: column, textBoxSize: commentSize)
        let result = sheet.comment(forCellAtRow: row, column: column)
        // then
        XCTAssertEqual(result, comment)
    }

    func testDeletingComments()
    {
        // XXX: comments only work in binary books (xls)
        book = nil
        book = Book(format: .Binary)
        sheet = try! book.add(sheetWithName: "whatever")
        // given
        let comment = "hi there"
        let row = 0, column = 0
        let commentSize = NSMakeSize(200, 100)
        // when
        sheet.write(comment: comment, forCellAtRow: row, column: column, textBoxSize: commentSize)
        let _ = sheet.remove(commentForCellAtRow: row, column: column)
        let result = sheet.comment(forCellAtRow: row, column: column)
        // then
        XCTAssertNil(result)
    }

    func testFetchingCellFormat()
    {
        // when
        let format = sheet.format(forCellAtRow: 1, column: 1)
        // then
        XCTAssertNotNil(format)
        XCTAssertEqual(format?.verticalAlignment, .Bottom)
        XCTAssertEqual(format?.numberFormat, .General)
    }

    func testSettingCellFormat()
    {
        // given
        let format = try! book.add(formatByCopying: nil)
        format.hidden = true
        format.shrinkToFit = true
        format.diagonalBorder = .Down(style: .MediumDashDotDot, color: .Pink)
        // when
        sheet.set(format: format, forCellAtRow: 1, column: 1)
        let fetched = sheet.format(forCellAtRow: 1, column: 1)
        // then
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.hidden, format.hidden)
        XCTAssertEqual(fetched?.shrinkToFit, format.shrinkToFit)
        XCTAssertEqual(fetched?.diagonalBorder, format.diagonalBorder)
    }

    func testWritingStringAndReadingStringCellValue()
    {
        // given
        let target = (1, 0)
        let stringValues = ["some string here", "second", "third"]

        // when
        let written = sheet.write(value: stringValues[0], toCell: target)
        // then
        XCTAssertTrue(written)

        // when
        let result = sheet.read(valueForCell: target)
        // then
        XCTAssertNotNil(result)
        if let contents = result, case let .String(value) = contents {
            XCTAssertEqual(value, stringValues[0])
        } else {
            XCTFail("Expected a string value")
        }
    }

    func testWritingStringAndReadingNumberCellValue()
    {
        // given
        let target = (1, 0)
        let stringValues = ["some string here", "second", "third"]

        // when
        let written = sheet.write(value: stringValues[0], toCell: target)
        // then
        XCTAssertTrue(written)

        // when
        let result = sheet.read(valueForCell: target)
        // then
        XCTAssertNotNil(result)
        if case let .Number(value) = result! {
            XCTFail("Expected a string value, not \(value)")
        }
    }

    func testWritingNumberAndReadingNumberCellValue()
    {
        // given
        let targets = [(1, 0), (2, 9)]
        let numberValues = [912.2, 17]

        // when
        let written0 = sheet.write(value: numberValues[0], toCell: targets[0])
        let written1 = sheet.write(value: numberValues[1], toCell: targets[1])
        // then
        XCTAssertTrue(written0)
        XCTAssertTrue(written1)

        // when
        let result0 = sheet.read(valueForCell: targets[0])
        let result1 = sheet.read(valueForCell: targets[1])
        // then
        XCTAssertNotNil(result0)
        XCTAssertNotNil(result1)
        if case let .Number(value0, _) = result0!, case let .Number(value1, _) = result1! {
            XCTAssertEqual(value0, numberValues[0])
            XCTAssertEqual(value1, numberValues[1])
        } else {
            XCTFail("Expected number values")
        }

    }

    func testWritingBooleanAndReadingBooleanCellValue()
    {
        // given
        let targets = [(9, 3), (12, 1)]
        let booleanValues = [false, true]

        // when
        let written0 = sheet.write(value: booleanValues[0], toCell: targets[0])
        let written1 = sheet.write(value: booleanValues[1], toCell: targets[1])

        // then
        XCTAssertTrue(written0)
        XCTAssertTrue(written1)

        // when
        let result0 = sheet.read(valueForCell: targets[0])
        let result1 = sheet.read(valueForCell: targets[1])
        // then
        XCTAssertNotNil(result0)
        XCTAssertNotNil(result1)
        if case let .Boolean(value0, _) = result0!, case let .Boolean(value1, _) = result1! {
            XCTAssertEqual(value0, booleanValues[0])
            XCTAssertEqual(value1, booleanValues[1])
        } else {
            XCTFail("Expected boolean values")
        }
    }

    func testWritingDateAndReadingDateCellValue()
    {
        // given
        let targets = [(41, 12), (4, 4)]
        let dates = [Date(), Date(timeIntervalSinceNow: 901)]

        // when
        let written0 = sheet.write(value: dates[0], toCell: targets[0])
        let written1 = sheet.write(value: dates[1], toCell: targets[1])
        // then
        XCTAssertTrue(written0)
        XCTAssertTrue(written1)

        // when
        let result0 = sheet.read(valueForCell: targets[0])
        let result1 = sheet.read(valueForCell: targets[1])
        // then
        XCTAssertNotNil(result0)
        XCTAssertNotNil(result1)
        if case let .Date(value0, _) = result0!, case let .Date(value1, _) = result1! {
            XCTAssertTrue(Calendar.current.isDate(value0, equalTo: dates[0], toGranularity: .second))
            XCTAssertTrue(Calendar.current.isDate(value1, equalTo: dates[1], toGranularity: .second))
        } else {
            XCTFail("Expected date values")
        }
    }

    func testFetchingAutoFilter()
    {
        XCTAssertNotNil(sheet.autoFilter)
    }

    func testApplyAutoFilter()
    {
        // given (if sorted by road injures)
        let topCountry = "UK",  topCountryCell = (3, 1)
        let topRoadInjures = 94, topRoadInjuresCell = (3, 2)

        // when
        sheet.write(value: "Country", toCell: (2, 1))
        sheet.write(value: "Road injures", toCell: (2, 2))
        sheet.write(value: "Smoking", toCell: (2, 3))
        sheet.write(value: "Suicide", toCell: (2, 4))

        sheet.write(value: "USA", toCell: (3, 1))
        sheet.write(value: 64, toCell: (3, 2))
        sheet.write(value: 69, toCell: (3, 3))
        sheet.write(value: 49, toCell: (3, 4))

        sheet.write(value: "UK", toCell: (4, 1))
        sheet.write(value: 94, toCell: (4, 2))
        sheet.write(value: 55, toCell: (4, 3))
        sheet.write(value: 64, toCell: (4, 4))

        sheet.autoFilter?.cellRange = AutoFilter.CellRange(rows: 2...4, columns: 1...4)
        sheet.autoFilter?.sortType = AutoFilter.SortType(column: 2, ascending: true)
        sheet.applyAutoFilter()

        // then
        let fetchedCountry = sheet.read(valueForCell: topCountryCell)
        if case let .String(value)? = fetchedCountry {
            XCTAssertEqual(value, topCountry)
        } else {
            XCTFail("Expected a country name at \(topCountryCell)")
        }
        // and then
        let fetchedRoadInjures = sheet.read(valueForCell: topRoadInjuresCell)
        if case let .Number(value, _)? = fetchedRoadInjures {
            XCTAssertEqual(Int(value), topRoadInjures)
        } else {
            XCTFail("Expected a road injures count at \(topRoadInjuresCell)")
        }
    }

    func testWritingFormulaWithoutPrecalculatedValue()
    {
        // given
        let formula = "100*(2-COS(0)"
        let target: (Int, Int) = (3, 41)
        // when
        let written = sheet.write(formula: formula, toCell: target)
        // then
        XCTAssertTrue(written)

        // when
        let fetchedFormula = sheet.read(formulaFromCell: target)
        // then
        XCTAssertEqual(formula, fetchedFormula)
    }

    func testWritingFormulaWithPrecalculatedDoubleValue()
    {
        // given
        let formula = "100*(2-COS(0)"
        let precalculated = 12.12
        let target: (Int, Int) = (3, 41)
        // when
        let written = sheet.write(formula: formula, toCell: target, withPrecalculatedResult: precalculated)
        // then
        XCTAssertTrue(written)

        // when
        let fetchedFormula = sheet.read(formulaFromCell: target)
        // then
        XCTAssertEqual(formula, fetchedFormula)
    }

    func testWritingFormulaWithPrecalculatedStringValue()
    {
        // given
        let formula = "100*(2-COS(0)"
        let precalculated = "dummy"
        let target: (Int, Int) = (3, 41)
        // when
        let written = sheet.write(formula: formula, toCell: target, withPrecalculatedResult: precalculated)
        // then
        XCTAssertTrue(written)

        // when
        let fetchedFormula = sheet.read(formulaFromCell: target)
        // then
        XCTAssertEqual(formula, fetchedFormula)
    }

    func testWritingFormulaWithPrecalculatedIntegerValue()
    {
        // given
        let formula = "100*(2-COS(0)"
        let precalculated = 9
        let target: (Int, Int) = (3, 41)
        // when
        let written = sheet.write(formula: formula, toCell: target, withPrecalculatedResult: precalculated)
        // then
        XCTAssertTrue(written)

        // when
        let fetchedFormula = sheet.read(formulaFromCell: target)
        // then
        XCTAssertEqual(formula, fetchedFormula)
    }

    func testReadingWritingCalculationErrors()
    {
        // given
        let error: Sheet.CalculationError = .Value
        let target: (Int, Int) = (3, 41)
        // when
        sheet.write(error: error, toCell: target)
        let fetchedError = sheet.read(errorFromCell: target)
        // then
        XCTAssertEqual(fetchedError, error)
    }

    func testFetchColumnWidth()
    {
        // given
        let column = 31
        // when
        let width = sheet.width(ofColumn: column)
        // then
        XCTAssertGreaterThan(width, 0)
    }

    func testSetingColumnWidth()
    {
        // given
        let column = 5, rawWidth = 14.0
        let width: Sheet.ColumnWidth = .Exactly(rawWidth)
        // when
        let status: ()? = try? sheet.set(width: width, forColumn: column, hidden: false)
        // then
        XCTAssertNotNil(status)

        // when
        let fetchedWidth = sheet.width(ofColumn: column)
        // then
        XCTAssertEqual(fetchedWidth, rawWidth)
    }

    func testFetchingRowHeight()
    {
        // given
        let row = 2
        // when
        let height = sheet.height(ofRow: row)
        // then
        XCTAssertGreaterThan(height, 0)
    }

    func testSettingRowHeight()
    {
        // given
        let row = 2
        let height = 12.81
        // when
        let status: ()? = try? sheet.set(height: height, forRow: row, hidden: false)
        // then
        XCTAssertNotNil(status)

        // when
        let fetchedHeight = sheet.height(ofRow: row)
        // then
        XCTAssertEqual(fetchedHeight, height)
    }

    func testFetchingColumnHidden()
    {
        // given
        let column = 41
        // when
        let hidden = sheet.hidden(column: column)
        // then
        XCTAssertEqual(hidden, false)
    }

    func testFetchingRowHidden()
    {
        // given
        let row = 2
        // when
        let hidden = sheet.hidden(row: row)
        // then
        XCTAssertEqual(hidden, false)
    }

    func testSettingRowHidden()
    {
        // given
        let row = 81
        let hidden = true
        // when
        sheet.hide(row: row)
        let fetchedHidden = sheet.hidden(row: row)
        // then
        XCTAssertEqual(fetchedHidden, hidden)
    }

    func testSettingColumnHidden()
    {
        // given
        let column = 7
        let hidden = true
        // when
        sheet.hide(column: column)
        let fetchedHidden = sheet.hidden(column: column)
        // then
        XCTAssertEqual(fetchedHidden, hidden)
    }

    func testMergingCells()
    {
        // given
        let mergeRange = Sheet.CellRange(rows: 4...7, columns: 2...6)
        let singleCell = (4, 5)
        // when
        let status: ()? = try? sheet.merge(cells: mergeRange)
        // then
        XCTAssertNotNil(status)

        // when
        let fetchedRange0 = sheet.rangeOfMergedCells(containingCell: singleCell)
        // merge at index 0 is the default "global" merge
        let fetchedRange1 = sheet.rangeOfMergedCells(atIndex: 1)
        // then
        XCTAssertEqual(fetchedRange0, mergeRange)
        XCTAssertEqual(fetchedRange1, mergeRange)
    }

    func testDeletingMerges()
    {
        // given
        let mergeRange = Sheet.CellRange(rows: 4...7, columns: 2...6)
        let singleCell = (4, 5)
        // when
        let mergeStatus: ()? = try? sheet.merge(cells: mergeRange)
        // then
        XCTAssertNotNil(mergeStatus)

        // when
        let deletionStatus: ()? = try? sheet.delete(mergeContainingCell: singleCell)
        // then
        XCTAssertNotNil(deletionStatus)
    }

    func testDeletingMergesByIndex()
    {
        // given
        let mergeRange = Sheet.CellRange(rows: 4...7, columns: 2...6)
        // when
        let mergeStatus: ()? = try? sheet.merge(cells: mergeRange)
        // then
        XCTAssertNotNil(mergeStatus)

        // when
        let deletionStatus = sheet.delete(mergedCellsAtIndex: 1)
        // then
        XCTAssertTrue(deletionStatus)
    }

    func testNumberOfMerges()
    {
        // given
        let mergeRange = Sheet.CellRange(rows: 4...7, columns: 2...6)
        // when
        try! sheet.merge(cells: mergeRange)
        // then
        XCTAssertEqual(sheet.numberOfMergedCells, 2)
    }

    func testFetchingName()
    {
        XCTAssertEqual(sheet.name, defaultSheetName)
    }

    func testSetName()
    {
        // given
        let newName = "foo"
        // when
        sheet.name = newName
        // then
        XCTAssertEqual(sheet.name, newName)
    }

    func testProtected()
    {
        XCTAssertEqual(sheet.protected, false)
        sheet.protected = true
        XCTAssertEqual(sheet.protected, true)
    }

    func testPaperSize()
    {
        XCTAssertEqual(sheet.paperSize, .Default)
        sheet.paperSize = .Envelope11
        XCTAssertEqual(sheet.paperSize, .Envelope11)
    }

    func testEnchancedProtections()
    {
        // given
        let protections: [Sheet.EnhancedProtection] = [.Sorting, .InsertingColumns]
        let password = "passw0rd"
        sheet.set(enchancedProtections: protections, password: password)
        sheet.remove(enchancedProtections: protections, password: password)
    }

    func testUsingPictures()
    {
        // given
        let pictureFile = samplePicture(named: "picture0")!
        let firstId = try! book.add(pictureFromFile: pictureFile)
        let secondId = try! book.add(pictureFromFile: pictureFile)
        let firstPictureLocation = (31, 1)
        let firstPictureWidth = 300, firstPictureHeight = 120
        let secondPictureLocation = (6, 0)
        // when
        sheet.set(picture: secondId, at: secondPictureLocation)
        sheet.set(picture: firstId, at: firstPictureLocation, width: firstPictureWidth, height: firstPictureHeight)
        // then
        XCTAssertEqual(sheet.numberOfPictures, 2)
        let fetchedSecondLocation = try? sheet.pictureLocation(atIndex: 0)
        XCTAssertEqual(fetchedSecondLocation?.identifier, secondId)
        XCTAssertEqual(fetchedSecondLocation?.topLeft.topRow, secondPictureLocation.0)
        let fetchedFirstLocation = try? sheet.pictureLocation(atIndex: 1)
        XCTAssertEqual(fetchedFirstLocation?.identifier, firstId)
        XCTAssertEqual(fetchedFirstLocation?.width, firstPictureWidth)
    }

    func testHorizontalPageBreaks()
    {
        XCTAssertEqual(sheet.rowWithHorizontalPageBreak(atIndex: 0), -1)
        XCTAssertEqual(sheet.rowWithHorizontalPageBreak(atIndex: 999), -1)
        XCTAssertEqual(sheet.numberOfHorizontalPageBreaks, 0)

        // given
        let rowWithPageBreak = 6
        // when
        let added: ()? = try? sheet.add(horizontalPageBreakAtRow: rowWithPageBreak)
        // then
        XCTAssertNotNil(added)
        XCTAssertEqual(sheet.rowWithHorizontalPageBreak(atIndex: 0), rowWithPageBreak)
        XCTAssertEqual(sheet.numberOfHorizontalPageBreaks, 1)
#if false // FIXME: xlSheetSetHorPageBreakA() always fails when you pass pageBreak=0
        // when
        let removed: ()? = try? sheet.remove(horizontalPageBreakAtRow: rowWithPageBreak)
        // then
        XCTAssertNotNil(removed)
        XCTAssertEqual(sheet.rowWithHorizontalPageBreak(atIndex: 0), -1)
#endif
    }

    func testVerticalPageBreaks()
    {
        XCTAssertEqual(sheet.columnWithVerticalPageBreak(atIndex: 0), -1)
        XCTAssertEqual(sheet.numberOfVerticalPageBreaks, 0)

        // given
        let columnWithPageBreak = 41
        // when
        let added: ()? = try? sheet.add(verticalPageBreakAtColumn: columnWithPageBreak)
        XCTAssertNotNil(added)
        XCTAssertEqual(sheet.columnWithVerticalPageBreak(atIndex: 0), columnWithPageBreak)
#if false // FIXME: xlSheetSetVerPageBreakA() always fails when you pass pageBreak=0
        let removed: ()? = try? sheet.remove(verticalPageBreakAtColumn: columnWithPageBreak)
        // then
        XCTAssertNotNil(removed)
        XCTAssertEqual(sheet.columnWithVerticalPageBreak(atIndex: 0), -1)
#endif
    }

    func testSplit()
    {
        XCTAssertEqual(sheet.splitPosition.row, 0)
        XCTAssertEqual(sheet.splitPosition.column, 0)

        // given
        let newPosition = (41, 12)
        // when
        sheet.split(sheetAtPosition: newPosition)
        // then
        XCTAssertEqual(sheet.splitPosition.row, newPosition.0)
        XCTAssertEqual(sheet.splitPosition.column, newPosition.1)
    }

    func testGroupingRowsAndColumns()
    {
        // given
        let rows = 3...19, columns = 9...71
        // when
        let grouppedRows: ()? = try? sheet.group(rows: rows, collapsing: true)
        let grouppedColumns: ()? = try? sheet.group(columns: columns, collapsing: false)
        // then
        XCTAssertNotNil(grouppedRows)
        XCTAssertNotNil(grouppedColumns)
    }

    func testGroupingSummary()
    {
        // given
        let verticalLocation = Sheet.GroupingSummaryVerticalLocation.Above
        let horizontalLocation = Sheet.GroupingSummaryHorizontalPosition.Left
        // when
        sheet.groupingSummaryVerticalLocation = verticalLocation
        sheet.groupingSummaryHorizontalLocation = horizontalLocation
        // then
        XCTAssertEqual(sheet.groupingSummaryVerticalLocation, verticalLocation)
        XCTAssertEqual(sheet.groupingSummaryHorizontalLocation, horizontalLocation)
    }

    func testClearingCells()
    {
        // given
        let cell = (4, 16)
        let contents = "13112"
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: cell))
        // and then
        sheet.clear(cells: Sheet.CellRange(rows: 3...4, columns: 14...19))
        guard case .Empty = sheet.read(valueForCell: cell)! else {
            XCTFail("Could not clean cells")
            return
        }
    }

    func testInsertingRows()
    {
        // given
        let cell = (4, 16)
        let newRow = cell.0 - 1 // insert one row above our cell
        let adjustedCell = (cell.0 + 1, cell.1)
        let contents = "13112"
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: cell))
        let inserted: ()? = try? sheet.insert(row: newRow)
        // then
        XCTAssertNotNil(inserted)
        if case let .String(value) = sheet.read(valueForCell: adjustedCell)! {
            XCTAssertEqual(value, contents)
        } else {
            XCTFail("Expected a string value")
        }

    }

    func testInsertingColumns()
    {
        // given
        let cell = (4, 16)
        let newColumns = (cell.1 - 1)...(cell.1 + 1) // insert three columns before our cell
        let adjustedCell = (cell.0, cell.1 + 3)
        let contents = 1337
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: cell))
        let inserted: ()? = try? sheet.insert(columns: newColumns)
        // then
        XCTAssertNotNil(inserted)
        if case let .Number(value, _) = sheet.read(valueForCell: adjustedCell)! {
            XCTAssertEqual(value, Double(contents))
        } else {
            XCTFail("Expected a string value")
        }
    }

    func testRemovingRows()
    {
        // given
        let cell = (7, 81)
        let rowsToRemove = 3...5
        let adjustedCell = (cell.0 - rowsToRemove.count, cell.1)
        let contents = "foo"
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: cell))
        let removed: ()? = try? sheet.remove(rows: rowsToRemove)
        // then
        XCTAssertNotNil(removed)
        if case let .String(value) = sheet.read(valueForCell: adjustedCell)! {
            XCTAssertEqual(value, contents)
        } else {
            XCTFail("Expected a string value")
        }
    }

    func testRemovingColumns()
    {
        // given
        let cell = (7, 81)
        let columnsToRemove = 3...5
        let adjustedCell = (cell.0, cell.1 - columnsToRemove.count)
        let contents = "foo"
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: cell))
        let removed: ()? = try? sheet.remove(columns: columnsToRemove)
        // then
        XCTAssertNotNil(removed)
        if case let .String(value) = sheet.read(valueForCell: adjustedCell)! {
            XCTAssertEqual(value, contents)
        } else {
            XCTFail("Expected a string value")
        }
    }

    func testCopyingCells()
    {
        // given
        let sourceCell = (7, 81)
        let destinationCell = (sourceCell.0 + 8, sourceCell.1 - 31)
        let contents = "foo"
        // when
        XCTAssertTrue(sheet.write(value: contents, toCell: sourceCell))
        let copied: ()? = try? sheet.copy(cell: sourceCell, to: destinationCell)
        // then
        XCTAssertNotNil(copied)
        if case let .String(value) = sheet.read(valueForCell: destinationCell)! {
            XCTAssertEqual(value, contents)
        } else {
            XCTFail("Expected a string value")
        }
    }

    func testFitToPage()
    {
        // given
        let options = Sheet.FitToPagePrintingOptions(enabled: true, widthInPages: 3, heightInPages: 4)
        // when
        sheet.fitToPagePrintingOptions = options
        // then
        XCTAssertEqual(sheet.fitToPagePrintingOptions, options)
    }

    func testHeader()
    {
        XCTAssertNil(sheet.header)
        // given
        let newHeader = Sheet.Header(format: "Hi there. Today is &D",
                                     margin: 0.9)
        // when
        sheet.header = newHeader
        // then
        XCTAssertEqual(sheet.header?.format, newHeader.format)
        XCTAssertEqual(sheet.header?.margin, newHeader.margin)
    }

    func testFooter()
    {
        XCTAssertNil(sheet.footer)
        // given
        let newFooter = Sheet.Footer(format: "Hi there. Today is &D",
                                     margin: 0.9)
        // when
        sheet.footer = newFooter
        // then
        XCTAssertEqual(sheet.footer?.format, newFooter.format)
        XCTAssertEqual(sheet.footer?.margin, newFooter.margin)
    }

    func testRepeatedRows()
    {
        XCTAssertNil(sheet.repeatedRows)
        // given
        let newRange = 4...9
        // when
        sheet.repeatedRows = newRange
        // then
        XCTAssertEqual(sheet.repeatedRows, newRange)

        // when
        sheet.clearPrintRepeats()
        // then
        XCTAssertNil(sheet.repeatedRows)
    }

    func testRepeatedColumns()
    {
        XCTAssertNil(sheet.repeatedColumns)
        // given
        let newRange = 4...9
        // when
        sheet.repeatedColumns = newRange
        // then
        XCTAssertEqual(sheet.repeatedColumns, newRange)
        // when
        sheet.clearPrintRepeats()
        // then
        XCTAssertNil(sheet.repeatedColumns)
    }

    func testPrintArea()
    {
        XCTAssertNil(sheet.printArea)
        // given
        let newPrintArea = Sheet.CellRange(rows: 12...81, columns: 1...6)
        // when
        sheet.printArea = newPrintArea
        // then
        XCTAssertEqual(sheet.printArea, newPrintArea)

        // when
        sheet.clearPrintArea()
        // then
        XCTAssertNil(sheet.printArea)
    }

    func testNamedRanges()
    {
        XCTAssertNil(sheet.namedRange(withName: "unknown", searchScope: .Global))

        // given
        let newGlobalRange = Sheet.NamedRange(name: "MyGlobalRange", cells: Sheet.CellRange(rows: 0...1, columns: 0...1))
        let newLocalRange = Sheet.NamedRange(name: "JustLocalOne", cells: Sheet.CellRange(rows: 1...9, columns: 7...66))
        // when
        let globalAdded: ()? = try? sheet.add(namedRange: newGlobalRange, scope: .Global)
        let localAdded: ()? = try? sheet.add(namedRange: newLocalRange, scope: .Sheet(atIndex: 0))
        // then
        XCTAssertNotNil(globalAdded)
        XCTAssertNotNil(localAdded)
        XCTAssertEqual(sheet.numberOfNamedRanges, 2)
        XCTAssertEqual(sheet.namedRange(withName: "MyGlobalRange", searchScope: .Global), newGlobalRange)
        XCTAssertEqual(sheet.namedRange(withName: "JustLocalOne", searchScope: .Sheet(atIndex: 0)), newLocalRange)
        XCTAssertEqual(sheet.namedRange(atIndex: 0), newGlobalRange)
        XCTAssertEqual(sheet.namedRange(atIndex: 1), newLocalRange)

        // when
        let deleted: ()? = try? sheet.delete(namedRange: "JustLocalOne", searchScope: .Sheet(atIndex: 0))
        // then
        XCTAssertNotNil(deleted)
        XCTAssertNil(sheet.namedRange(atIndex: 1))
        XCTAssertNil(sheet.namedRange(withName: "JustLocalOne", searchScope: .Sheet(atIndex: 0)))
    }

    func testTables()
    {
        XCTAssertEqual(sheet.numberOfTables, 0)
    }

    func testHyperlinks()
    {
        XCTAssertEqual(sheet.numberOfHyperlinks, 0)
        XCTAssertNil(sheet.hyperlink(atIndex: 0))

        // given
        let newHyperlink = Sheet.Hyperlink(value: "http://google.com", occupiedCells: Sheet.CellRange(rows: 4...5, columns: 0...0))

        // when
        sheet.add(hyperlink: newHyperlink)
        // then
        XCTAssertEqual(sheet.numberOfHyperlinks, 1)
        XCTAssertEqual(sheet.hyperlink(atIndex: 0), newHyperlink)

        // when
        sheet.delete(hyperlinkAtIndex: 0)
        // then
        XCTAssertEqual(sheet.numberOfHyperlinks, 0)
        XCTAssertNil(sheet.hyperlink(atIndex: 0))
    }

    func testCellReferencesToCells()
    {
        // given
        let references = ["A1", "BC12", "B$8", "$B9", "$C$12"]
        let cells = [(0, 0), (11, 54), (7, 1), (8, 1), (11, 2)]
        // when
        let results = references.map { sheet.cellReferenceToCell($0) }
        // then
        XCTAssertTrue((results[0].row, results[0].column) == cells[0])
        XCTAssertTrue((results[1].row, results[1].column) == cells[1])
        XCTAssertTrue((results[2].row, results[2].column) == cells[2])
        XCTAssertTrue((results[3].row, results[3].column) == cells[3])
        XCTAssertTrue((results[4].row, results[4].column) == cells[4])
        // A1
        XCTAssertTrue(results[0].relativeRow)
        XCTAssertTrue(results[0].relativeColumn)
        // BC12
        XCTAssertTrue(results[1].relativeRow)
        XCTAssertTrue(results[1].relativeColumn)
        // B$8
        XCTAssertFalse(results[2].relativeRow)
        XCTAssertTrue(results[2].relativeColumn)
        // $B9
        XCTAssertTrue(results[3].relativeRow)
        XCTAssertFalse(results[3].relativeColumn)
        // $C$12
        XCTAssertFalse(results[4].relativeRow)
        XCTAssertFalse(results[4].relativeColumn)
    }

    func testCellToCellReference()
    {
        // given
        let cells = [(0, 0, true, true), (11, 54, true, true), (7, 1, false, true), (8, 1, true, false), (11, 2, false, false)].map {
            Sheet.CellLookup(row: $0, column: $1, relativeRow: $2, relativeColumn: $3)
        }
        let references = ["A1", "BC12", "B$8", "$B9", "$C$12"]
        // when
        let results = cells.map { sheet.cellToCellReference($0) }
        let unwrappedResults = results.flatMap {$0}
        // then
        XCTAssertEqual(results.count, unwrappedResults.count)
        XCTAssertEqual(unwrappedResults, references)
    }
}
