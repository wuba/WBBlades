//
//  BookTests.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 17/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import XCTest
import SwiftyXL

class BookTests: SwiftyXLTestCase
{
    // MARK: - State

    var book: Book? = nil

    // MARK: - Misc

    override func setUp()
    {
        super.setUp()
        book = Book()
    }

    override func tearDown() {
        book = nil
        cleanupTemporaryFiles()
        super.tearDown()
    }

    func testLastErrorMessage()
    {
        XCTAssertEqual(book!.lastErrorMessage, "ok")
        do {
            try book!.load(fromFile: "obviously invalid file name . png")
        } catch { }
        XCTAssertNotEqual(book!.lastErrorMessage, "ok")
    }

    // MARK: - Save/Load

    func testLoadingXLSFileIntoBinaryBookSucceeds()
    {
        // given
        book = nil
        book = Book(format: .Binary)
        let path = sampleBook(named: "book0.xls")!
        // when
        let loaded: ()? = try? book!.load(fromFile: path)
        // then
        XCTAssertNotNil(loaded)
    }

    func testLoadingXLSFileIntoXMLBookFails()
    {
        // given
        book = nil
        book = Book(format: .XML)
        let path = sampleBook(named: "book0.xls")!
        // when
        let loaded: ()? = try? book!.load(fromFile: path)
        // then
        XCTAssertNil(loaded)
    }

    func testLoadingXMLFileIntoXMLBookSucceeds()
    {
        // given
        book = nil
        book = Book(format: .XML)
        let path = sampleBook(named: "book1.xlsx")!
        // when
        let loaded: ()? = try? book!.load(fromFile: path)
        // then
        XCTAssertNotNil(loaded)
    }

    func testLoadingXMLFileIntoBinaryBookFails()
    {
        // given
        book = nil
        book = Book(format: .Binary)
        let path = sampleBook(named: "book1.xlsx")!
        // when
        let loaded: ()? = try? book!.load(fromFile: path)
        // then
        XCTAssertNil(loaded)
    }

    func testLoadingFromFile()
    {
        // given
        let path = sampleBook(named: "book1.xlsx")!
        // when
        let loaded: ()? = try? book!.load(fromFile: path)
        // then
        XCTAssertNotNil(loaded, "Can't load Book from a file")
    }

    func testLoadingFromData()
    {
        // given
        let path = sampleBook(named: "book1.xlsx")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: path))
        // when
        let loaded: ()? = try? book!.load(fromData: data)
        // then
        XCTAssertNotNil(loaded, "Can't load Book from data")
    }

    func testSavingToFile()
    {
        // given
        let filename = "output_testSavingToFile.xlsx"
        // when
        let saved: ()? = try? book!.save(toFile: path(forTemporaryFile: filename))
        // then
        XCTAssertNotNil(saved, "Could not save Book to a file")
    }

    func testSaveToData()
    {
        // when
        let result = try? book!.save()
        // then
        XCTAssertNotNil(result, "Could not save Book as data")
        let data = result!
        XCTAssertNotNil(data, "Saved data is invalid")
        XCTAssertGreaterThan(data!.count, 0)
    }


    // MARK: - Sheets

    func testAddingNewSheet()
    {
        // given
        let sheetName = "some sheet"
        // when
        let result = try? book!.add(sheetWithName: sheetName)
        XCTAssertNotNil(result, "Could not add new sheet")
    }

    func testAddingNewSheetByCopyingExistingOne()
    {
        // given
        let firstSheetName = "some sheet"
        let secondSheetName = "another one"
        // when
        let firstResult = try! book!.add(sheetWithName: firstSheetName)
        let secondResult = try? book!.add(sheetWithName: secondSheetName, byCopying: firstResult)
        // then
        XCTAssertNotNil(secondResult, "Could not add new sheet by copying an existing one")
    }

    func testInsertingNewSheet()
    {
        // given
        let sheetName = "some sheet"
        let destination = 0
        // when
        let result = try? book!.insert(sheetWithName: sheetName, atIndex: destination)
        // then
        XCTAssertNotNil(result, "Could not insert new sheet at index \(destination)")
    }

    func testInsertingNewSheetByCopyingExistingOne()
    {
        // given
        let names = ["first", "second", "third"]
        let destination = 1
        let first = try! book!.add(sheetWithName: names[0])
        let _ = try! book!.add(sheetWithName: names[2])
        // when
        let result = try? book!.insert(sheetWithName: names[1], atIndex: destination, byCopying: first)
        XCTAssertNotNil(result, "Could not insert new sheet at index \(destination)")
    }

    func testAccessingSheets()
    {
        // given
        let names = ["first", "second", "third"]
        // when
        let _ = try! book!.add(sheetWithName: names[0])
        let second = try! book!.add(sheetWithName: names[1])
        let _ = try! book!.add(sheetWithName: names[2])
        let fetched = book!.sheet(atIndex: 1)
        // then
        XCTAssertEqual(fetched?.name, second.name)
    }

    func testFetchingSheetType()
    {
        // given
        let name = "some sheet"
        // when
        let _ = try! book!.add(sheetWithName: name)
        let type = book!.type(ofSheetAtIndex: 0)
        // then
        XCTAssertEqual(type, SheetType.Standart)
    }

    func testFetchingSheetTypeByIndex()
    {
        // given
        let name = "some sheet"
        // when
        let _ = try! book!.add(sheetWithName: name)
        let type = book!.type(ofSheetAtIndex: 0)
        // then
        XCTAssertEqual(type, SheetType.Standart)
    }

    func testFetchingNumberOfSheets()
    {
        // given
        let names = ["first", "second", "third"]
        // when
        let _ = try! book!.add(sheetWithName: names[0])
        let _ = try! book!.add(sheetWithName: names[1])
        let _ = try! book!.add(sheetWithName: names[2])

        let number = book!.numberOfSheets
        // then
        XCTAssertEqual(number, 3)
    }

    func testDeletingSheets()
    {
        // given
        let names = ["first", "second", "third"]
        // when
        let _ = try! book!.add(sheetWithName: names[0])
        let _ = try! book!.add(sheetWithName: names[1])
        let _ = try! book!.add(sheetWithName: names[2])
        let result: ()? = try? book!.delete(sheetAtIndex: 2)
        // then
        XCTAssertNotNil(result, "Could not remove the third sheet")
    }

    func testFetchingDefaultSheet()
    {
        // given
        let name = "default sheet"
        // when
        let _ = try! book!.add(sheetWithName: name)
        let activeSheet = book!.activeSheet
        // then
        XCTAssertEqual(activeSheet, 0)
    }

    // MARK: - Formats

    func testAddingNewFormat()
    {
        // given
        // when
        let format = try? book!.add(formatByCopying: nil)
        // then
        XCTAssertNotNil(format)
    }

    func testAddingNewFormatByCopyingExistingOne()
    {
        // given
        // when
        let existingFormat = try! book!.add(formatByCopying: nil)
        let result = try? book!.add(formatByCopying: existingFormat)
        // then
        XCTAssertNotNil(result, "Could not copy existing format")

    }

    func testAccessingFormats()
    {
        // given
        // when
        let _ = try! book!.add(formatByCopying: nil)
        let fetched = book!.format(atIndex: 0)
        // then
        XCTAssertNotNil(fetched)
    }

    func testAccessingInvalidFormats()
    {
        // given
        // when
        let _ = try! book!.add(formatByCopying: nil)
        let fetched = book!.format(atIndex: 1337)
        // then
        XCTAssertNil(fetched)
    }

    func testFetchingNumberOfFormats()
    {
        // given
        // when
        let oldCount  = book!.numberOfFormats
        let _ = try! book!.add(formatByCopying: nil)
        let _ = try! book!.add(formatByCopying: nil)
        let newCount = book!.numberOfFormats
        // then
        XCTAssertEqual(newCount - oldCount, 2)
    }

    // MARK: - Custom Formats

    func testAddingCustomNumberFormats()
    {
        // given
        let format = "#.000"
        // when
        let formatId = try? book!.add(customNumberFormat: format)
        // then
        XCTAssertNotNil(formatId)
    }

    func testAccessingCustomNumberFormats()
    {
        // given
        let format = "#.000"
        // when
        let formatId = try! book!.add(customNumberFormat: format)
        let result = try? book!.customNumberFormat(withIdentifier: formatId)
        // then
        XCTAssertNotNil(result)
        XCTAssertEqual(result!, format)
    }

    // MARK: - Fonts

    func testAddingNewFont()
    {
        // given
        // when
        let result = try? book!.add(fontByCopying: nil)
        // then
        XCTAssertNotNil(result)
    }

    func testAddingNewFontByCopyingExistingOne()
    {
        // given
        // when
        let existingFont = try! book!.add(fontByCopying: nil)
        let result = try? book!.add(fontByCopying: existingFont)
        // then
        XCTAssertNotNil(result)
    }

    func testFetchingNumberOfFonts()
    {
        // given
        // when
        let oldCount = book!.numberOfFonts
        let _ = try! book!.add(fontByCopying: nil)
        let _ = try! book!.add(fontByCopying: nil)
        let newCount = book!.numberOfFonts
        // then
        XCTAssertEqual(newCount - oldCount, 2)
    }

    func testAccessingFonts()
    {
        // given
        // when
        let idx = book!.numberOfFonts
        let font = try! book!.add(fontByCopying: nil)
        let _ = try! book!.add(fontByCopying: nil)
        let fetched = book!.font(atIndex: idx)
        // then
        XCTAssertEqual(fetched?.name, font.name)
        XCTAssertEqual(fetched?.size, font.size)
    }

    func testFetchingDefaultFont()
    {
        // given
        // when
        let defaultFont = book!.defaultFont
        // then
        XCTAssertNotNil(defaultFont)
    }

    func testSettingDefaultFont()
    {
        // given
        let newDefault = DefaultBookFont(name: "Times New Roman", size: 14)
        // when
        book!.defaultFont = newDefault
        let fetched = book!.defaultFont
        // then
        XCTAssertEqual(fetched, newDefault)
    }


    // MARK: - Pictures

    func testAddingPicturesFromFile()
    {
        // given
        let file = samplePicture(named: "picture0")!
        // when
        let _ = try? book!.add(pictureFromFile: file)
        let id = try? book!.add(pictureFromFile: file)

        // then
        XCTAssertNotNil(id)
        XCTAssertGreaterThanOrEqual(id!, 0)
    }

    func testAddingPicturesFromRawData()
    {
        // given
        let file = samplePicture(named: "picture0")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: file))
        // when
        let id = try? book!.add(pictureFromData: data)
        // then
        XCTAssertNotNil(id)
        XCTAssertGreaterThanOrEqual(id!, 0)
    }

    func testFetchingNumberOfPictures()
    {
        // given
        let file = samplePicture(named: "picture0")!
        // when
        let _ = try! book!.add(pictureFromFile: file)
        let count = book!.numberOfPictures
        // then
        XCTAssertEqual(count, 1)
    }

    func testAccessingPictures()
    {
        // given
        let file = samplePicture(named: "picture0")!
        // when
        let identifier = try! book!.add(pictureFromFile: file)
        let fetched = try? book!.picture(atIndex: identifier)
        // then
        XCTAssertNotNil(fetched)
        XCTAssertNotEqual(fetched?.data.count, 0)
    }

    // MARK: - Properties

    func testTogglinRGBMode()
    {
        // when
        book!.rgbMode = .Index
        // then
        XCTAssertEqual(book!.rgbMode.rawValue, Book.ColorMode.Index.rawValue)
        // when
        book!.rgbMode = .RGB
        // then
        XCTAssertEqual(book!.rgbMode.rawValue, Book.ColorMode.RGB.rawValue)
        // when
        book!.rgbMode = .Index
        // then
        XCTAssertEqual(book!.rgbMode.rawValue, Book.ColorMode.Index.rawValue)
    }

    func testTogglinR1C1Mode()
    {
        // when
        book!.R1C1Mode = false
        // then
        XCTAssertEqual(book!.R1C1Mode, false)
        // when
        book!.R1C1Mode = true
        // then
        XCTAssertEqual(book!.R1C1Mode, true)
    }

    func testReadingBiffVersion()
    {
        switch book!.format {
        case .XML:
            XCTAssertEqual(book!.biffVersion, 0)
        case .Binary:
            XCTAssertNotEqual(book!.biffVersion, 0)
        }
    }

    func testTogglingDateMode()
    {
        // when
        book!.dateMode = .Date1900
        // then
        XCTAssertEqual(book!.dateMode, .Date1900)
        // when
        book!.dateMode = .Date1904
        // then
        XCTAssertEqual(book!.dateMode, .Date1904)
        // when
        book!.dateMode = .Date1900
        // then
        XCTAssertEqual(book!.dateMode, .Date1900)
    }

    func testTogglingTemplete()
    {
        // when
        book!.template = false
        // then
        XCTAssertEqual(book!.template, false)
        // when
        book!.template = true
        // then
        XCTAssertEqual(book!.template, true)
        // when
        book!.template = false
        // then
        XCTAssertEqual(book!.template, false)
    }

    func testSettingLocale()
    {
        // given
        let locale = "en_US.UTF-8"
        // when
        let result: ()? = try? book!.use(locale: locale)
        // then
        XCTAssertNotNil(result)
    }

    // MARK: - Value Packing & Unpacking
    // TODO: this
}
