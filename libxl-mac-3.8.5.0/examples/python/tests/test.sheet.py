import unittest
from libxlpy import *

class TestSheet(unittest.TestCase):
    def setUp(self):
        self.book = Book()
        self.sheet = self.book.addSheet('foo')

    def test_cellType(self):
        type = self.sheet.cellType(0, 0)
        self.assertIn(
                type,
                [SHEETTYPE_CHART, SHEETTYPE_SHEET, SHEETTYPE_UNKNOWN])

    def test_isFormula(self):
        self.assertFalse(
                self.sheet.isFormula(0, 0))

    def test_cellFormat(self):
        self.assertIsNone(self.sheet.cellFormat(0,0))

    def test_setCellFormat(self):
        fmt = self.book.addFormat()
        fmt.setNumFormat(NUMFORMAT_ACCOUNT_D2_CUR)

        self.sheet.setCellFormat(3, 3, fmt)
        fmt = self.sheet.cellFormat(3, 3)

        # num format should be equals for the same cell
        self.assertEqual(NUMFORMAT_ACCOUNT_D2_CUR,
                fmt.numFormat())

    def test_readStr(self):
        (text, fmt) = self.sheet.readStr(0, 0)
        self.assertEqual(text,
                "Created by LibXL trial version. Please buy the LibXL full version for removing this message.")
        self.assertIsNone(fmt)

        self.sheet.writeStr(2, 2, "Hello!")
        (text, fmt) = self.sheet.readStr(2, 2)
        self.assertEqual("Hello!", text)
        self.assertEqual('XLPyFormat', type(fmt).__name__)

    def test_writeStr(self):
        # Trial Version return False on 0,0
        self.assertFalse(
                self.sheet.writeStr(0, 0, "Hello World"))

        self.assertTrue(
                self.sheet.writeStr(1, 0, "Hello World"))
        
        (txt, fmt) = self.sheet.readStr(1, 0)
        self.sheet.writeStr(1, 0, "Hello with Format", fmt)

    def test_readNum(self):
        self.sheet.writeNum(3, 3, 200)
        (num, fmt) = self.sheet.readNum(3, 3)
        self.assertEqual(200.0, num)
        self.assertEqual('XLPyFormat', type(fmt).__name__)

    def test_writeNum(self):
        self.assertTrue(
                self.sheet.writeNum(1, 1, 20.0))

        self.assertTrue(
                self.sheet.writeNum(1, 1, 20))

        with self.assertRaises(TypeError):
            self.sheet.writeNum(1, 1, "twenty")

        (num, fmt) = self.sheet.readNum(1, 1)
        self.sheet.writeNum(1, 1, 10, fmt)

    def test_readBool(self):
        self.assertTrue(self.sheet.writeBool(3, 3, False))
        self.assertFalse(self.sheet.readBool(3, 3)[0])

        self.assertTrue(self.sheet.writeBool(3, 3, True))
        self.assertTrue(self.sheet.readBool(3, 3)[0])

    def test_writeBool(self):
        # error with unregistered lib
        self.assertFalse(self.sheet.writeBool(0, 0, True))
        self.assertTrue(self.sheet.writeBool(1, 1, True))
        self.assertTrue(self.sheet.writeBool(1, 1, False))
        
        (val, fmt) = self.sheet.readBool(1, 1)
        self.sheet.writeBool(3, 3, True, fmt)

    def test_readBlank(self):
        (val, fmt) = self.sheet.readBlank(0, 0)
        self.assertFalse(val)
        self.assertIsNone(fmt)

    def test_writeBlank(self):
        self.assertFalse(self.sheet.writeBlank(0, 0))
        self.sheet.writeBlank(3, 3)
        (val, fmt) = self.sheet.readBlank(3, 3)
        self.assertTrue(val)

    def test_readFormula(self):
        self.assertEqual(
                (None, None),
                self.sheet.readFormula(0, 0)
        )

    def test_writeFormula(self):
        # can't write row 0 in trial version
        self.assertFalse(self.sheet.writeFormula(0, 0, '=3+3'))

        # incorrect token in formula
        self.assertFalse(self.sheet.writeFormula(1, 0, 'incorrect_token'))

        self.assertTrue(self.sheet.writeFormula(1, 0, '=3+3'))
        (val, fmt) = self.sheet.readFormula(1, 0)
        self.assertEqual('3+3', val)

    def test_readComment(self):
        self.assertIsNone(self.sheet.readComment(0, 0))

    def test_writeComment(self):
        self.assertIsNone(
                self.sheet.writeComment(0, 0, 'comment', 'author', 10, 10))

        self.assertEqual('comment',
                self.sheet.readComment(0, 0))

        self.assertIsNone( self.sheet.writeComment(0, 0,
            'passing just this param should also work'))

    def test_isDate(self):
        self.assertFalse(self.sheet.isDate(0, 0))

    def test_readError(self):
        self.assertEqual(ERRORTYPE_NOERROR, self.sheet.readError(0, 0));

    def test_colWidth(self):
        val = self.sheet.colWidth(0)
        self.assertTrue( isinstance(val, float) )

    def test_rowHeight(self):
        val = self.sheet.rowHeight(0)
        self.assertTrue( isinstance(val, float) )

    def test_setCol(self):
        self.assertTrue(self.sheet.setCol(0, 10, 20))
        self.assertTrue(self.sheet.setCol(0, 10, 20.0, hidden = True))

    def test_setRow(self):
        self.assertFalse(self.sheet.setRow(0, 20))
        self.assertTrue(self.sheet.setRow(1, 20))
        self.sheet.setRow(0, 20.0, hidden = True)

    def test_rowHidden(self):
        self.assertFalse(self.sheet.rowHidden(0))
        self.assertFalse(self.sheet.rowHidden(1))

    def test_setRowHidden(self):
        self.assertFalse(self.sheet.setRowHidden(0, True)) # trial version error

        self.sheet.setRowHidden(1, True)
        self.assertTrue(self.sheet.rowHidden(1))

        self.sheet.setRowHidden(1, False)
        self.assertFalse(self.sheet.rowHidden(1))

    def test_colHidden(self):
        self.assertFalse(self.sheet.colHidden(0))
        self.assertFalse(self.sheet.colHidden(1))

    def test_setColHidden(self):
        self.sheet.setColHidden(1, True)
        self.assertTrue(self.sheet.colHidden(1))

        self.sheet.setColHidden(1, False)
        self.assertFalse(self.sheet.colHidden(1))

    def test_getMerge(self):
        self.assertEqual(
            (0, 0, 0, 255),
            self.sheet.getMerge(0, 0)
        )
        self.assertIsNone(self.sheet.getMerge(1, 1))

    def test_setMerge(self):
        self.assertTrue(self.sheet.setMerge(3, 3, 3, 3))
        self.assertEqual(
            (3, 3, 3, 3),
            self.sheet.getMerge(3, 3)
        )
        self.assertFalse(self.sheet.setMerge(0, 0, -3, -3))

    def test_delMerge(self):
        self.sheet.setMerge(3, 3, 5, 5)

        self.assertIsNotNone(self.sheet.getMerge(3, 5))
        self.sheet.delMerge(3, 5)
        self.assertIsNone(self.sheet.getMerge(3, 5))

    def test_pictureSize(self):
        self.assertEqual(0, self.sheet.pictureSize())

    def test_getPicture(self):
        # no picture found
        self.assertIsNone(self.sheet.getPicture(0)) 

    def test_setPicture(self):
        img = self.book.addPicture('./logo.png')
        self.assertIsNone(self.sheet.setPicture(0, 0, img, 1, 0, 0))
        self.assertEqual(1, self.sheet.pictureSize())

        match = ( (0, 0), 5, 1, 100, 100, 0, 0 )
        self.assertEqual(match, self.sheet.getPicture(img))

    def test_setPicture2(self):
        img = self.book.addPicture('./logo.png')
        self.assertIsNone(self.sheet.setPicture2(0, 0, img, 100, 100, 0, 0))
        self.assertEqual(1, self.sheet.pictureSize())

    def test_getHorPageBreak(self):
        self.assertEqual(-1, self.sheet.getHorPageBreak(0))

    def test_getHorPageBreakSize(self):
        self.assertEqual(0, self.sheet.getHorPageBreakSize())

    def test_getVerPageBreak(self):
        self.assertEqual(-1, self.sheet.getVerPageBreak(0))

    def test_getVerPageBreakSize(self):
        self.assertEqual(0, self.sheet.getVerPageBreakSize())

    def test_setHorPageBreak(self):
        self.assertEqual(0, self.sheet.getHorPageBreakSize())
        self.sheet.setHorPageBreak(1, True)
        self.assertEqual(1, self.sheet.getHorPageBreakSize())

    def test_setVerPageBreak(self):
        self.assertEqual(0, self.sheet.getVerPageBreakSize())
        self.sheet.setVerPageBreak(1, True)
        self.assertEqual(1, self.sheet.getVerPageBreakSize())

    def test_split(self):
        self.assertIsNone(self.sheet.split(0, 0))
        self.assertIsNone(self.sheet.split(10, 10))

    def test_groupRows(self):
        self.assertTrue( self.sheet.groupRows(0, 10, True) )
        self.assertTrue( self.sheet.groupRows(0, 10, False) )
    
    def test_groupCols(self):
        self.assertTrue( self.sheet.groupCols(0, 10, True) )
        self.assertTrue( self.sheet.groupCols(0, 10, False) )

    def test_groupSummaryBelow(self):
        self.assertTrue( self.sheet.groupSummaryBelow() )

    def test_setGroupSummaryBelow(self):
        self.sheet.setGroupSummaryBelow(False)
        self.assertFalse( self.sheet.groupSummaryBelow() )
        
        self.sheet.setGroupSummaryBelow(True)
        self.assertTrue( self.sheet.groupSummaryBelow() )

    def test_groupSummaryRight(self):
        self.assertTrue( self.sheet.groupSummaryRight() )

    def test_setGroupSummaryRight(self):
        self.sheet.setGroupSummaryRight(False)
        self.assertFalse( self.sheet.groupSummaryRight() )
        
        self.sheet.setGroupSummaryRight(True)
        self.assertTrue( self.sheet.groupSummaryRight() )

    def test_clear(self):
        self.sheet.writeStr( 1,  1, 'foo')
        self.sheet.writeStr( 5,  5, 'bar')
        self.sheet.writeStr(10, 10, 'foobar')

        self.sheet.clear(0, 5, 0, 5)

        self.assertIsNone( self.sheet.readStr( 1,  1) )
        self.assertIsNone( self.sheet.readStr( 5,  5) )
        self.assertEqual('foobar', self.sheet.readStr(10, 10)[0])

    def test_insertRow(self):
        # trial version error
        self.assertFalse(self.sheet.insertRow(0, 1))

        # argument error
        self.assertFalse(self.sheet.insertRow(1, 0))

        self.assertTrue(self.sheet.insertRow(1, 10))

    def test_insertCol(self):
        # trial version error
        self.assertFalse(self.sheet.insertCol(0, 1))

        # argument error
        self.assertFalse(self.sheet.insertCol(1, 0))

        self.assertTrue(self.sheet.insertCol(1, 10))

    def test_removeRow(self):
        self.assertFalse(self.sheet.removeRow(0, 1))
        self.assertFalse(self.sheet.removeRow(1, 0))

        self.sheet.writeStr(1, 0, 'foo')
        self.assertTrue(self.sheet.removeRow(1, 1))
        self.assertIsNone( self.sheet.readStr(1, 0) )

    def test_removeCol(self):
        self.assertFalse(self.sheet.removeCol(0, 1))
        self.assertFalse(self.sheet.removeCol(1, 0))

        self.sheet.writeStr(1, 1, 'foo')
        self.assertTrue(self.sheet.removeCol(1, 10))
        self.assertIsNone( self.sheet.readStr(1, 1) )

    def test_copyCell(self):
        self.sheet.writeStr(1, 1, 'foo')
        self.sheet.copyCell(1, 1, 2, 2)
        (str, fmt) = self.sheet.readStr(2, 2)
        self.assertEqual('foo', str)

        # trial error
        self.assertFalse(self.sheet.copyCell(0, 0, 1, 1))

    def test_firstRow(self):
        self.assertEqual(0, self.sheet.firstRow())

    def test_lastRow(self):
        self.sheet.writeStr(10, 0, 'foo')
        self.assertEqual(11, self.sheet.lastRow())

    def test_firstCol(self):
        self.assertEqual(0, self.sheet.firstCol())

    def test_lastCol(self):
        self.sheet.writeStr(1, 10, 'foo')
        self.assertEqual(11, self.sheet.lastCol())

    def test_displayGridlines(self):
        self.assertIsInstance(self.sheet.displayGridlines(), bool)

    def test_setDisplayGridlines(self):
        self.sheet.setDisplayGridlines(True)
        self.assertTrue(self.sheet.displayGridlines())
        
        self.sheet.setDisplayGridlines(False)
        self.assertFalse(self.sheet.displayGridlines())
    
    def test_printGridlines(self):
        self.assertIsInstance(self.sheet.printGridlines(), bool)

    def test_setPrintGridlines(self):
        self.sheet.setPrintGridlines(True)
        self.assertTrue(self.sheet.printGridlines())
        
        self.sheet.setPrintGridlines(False)
        self.assertFalse(self.sheet.printGridlines())

    def test_zoom(self):
        self.assertIsInstance(self.sheet.zoom(), int)

    def test_setZoom(self):
        self.sheet.setZoom(200)
        self.assertEquals(200, self.sheet.zoom())

    def test_getPrintFit(self):
        self.assertIsInstance(self.sheet.getPrintFit(), tuple)

    def test_setPrintFit(self):
        self.sheet.setPrintFit(10, 20)
        self.assertEquals(self.sheet.getPrintFit(), (10, 20))

    def test_landscape(self):
        self.assertIsInstance(self.sheet.landscape(), bool)

    def test_setLandscape(self):
        self.sheet.setLandscape(True)
        self.assertTrue(self.sheet.landscape())

        self.sheet.setLandscape(False)
        self.assertFalse(self.sheet.landscape())

    def test_paper(self):
        self.assertEquals(self.sheet.paper(), PAPER_DEFAULT) 

    def test_setPaper(self):
        self.sheet.setPaper(PAPER_FOLIO)
        self.assertEquals(self.sheet.paper(), PAPER_FOLIO)

    def test_header(self):
        self.assertIsNone(self.sheet.header())

    def test_setHeader(self):
        hdr = "Header Text"
        self.sheet.setHeader(hdr, 10)
        self.assertEquals(hdr, self.sheet.header())
    
    def test_headerMargin(self):
        self.assertIsInstance(self.sheet.headerMargin(), float)

        margin = 10.0
        self.sheet.setHeader("foo", margin)
        self.assertEquals(margin, self.sheet.headerMargin())

    def test_footer(self):
        self.assertIsNone(self.sheet.footer())

    def test_setFooter(self):
        ftr = "Footer Text"
        self.sheet.setFooter(ftr, 10)
        self.assertEquals(ftr, self.sheet.footer())
    
    def test_footerMargin(self):
        self.assertIsInstance(self.sheet.footerMargin(), float)

        margin = 10.0
        self.sheet.setFooter("foo", margin)
        self.assertEquals(margin, self.sheet.footerMargin())

    def test_hCenter(self):
        self.assertIsInstance(self.sheet.hCenter(), bool)

    def test_setHCenter(self):
        self.sheet.setHCenter(True)
        self.assertTrue(self.sheet.hCenter())

        self.sheet.setHCenter(False)
        self.assertFalse(self.sheet.hCenter())

    def test_vCenter(self):
        self.assertIsInstance(self.sheet.vCenter(), bool)

    def test_setVCenter(self):
        self.sheet.setVCenter(True)
        self.assertTrue(self.sheet.vCenter())

        self.sheet.setHCenter(False)
        self.assertFalse(self.sheet.hCenter())

    def test_Margins(self):
        margin = 10.0

        self.sheet.setMarginLeft(margin)
        self.assertEquals(margin, self.sheet.marginLeft())

        self.sheet.setMarginRight(margin)
        self.assertEquals(margin, self.sheet.marginRight())
        
        self.sheet.setMarginTop(margin)
        self.assertEquals(margin, self.sheet.marginTop())

        self.sheet.setMarginBottom(margin)
        self.assertEquals(margin, self.sheet.marginBottom())

    def test_printRowCol(self):
        self.assertIsInstance(self.sheet.printRowCol(), bool)

    def test_setPrintRowCol(self):
        self.sheet.setPrintRowCol(True)
        self.assertTrue(self.sheet.printRowCol())

        self.sheet.setPrintRowCol(False)
        self.assertFalse(self.sheet.printRowCol())

    def test_setPrintRepeatedRows(self):
        self.assertIsNone( self.sheet.setPrintRepeatedRows(1, 10) )

    def test_setPrintRepeatedCols(self):
        self.assertIsNone( self.sheet.setPrintRepeatedCols(1, 10) )

    def test_setPrintArea(self):
        self.assertIsNone( self.sheet.setPrintArea(1, 10, 1, 10) )

    def test_getNamedRange(self):
        self.assertIsNone(self.sheet.getNamedRange("foo"))

    def test_clearPrintRepeats(self):
        self.assertIsNone(self.sheet.clearPrintRepeats())

    def test_clearPrintArea(self):
        self.assertIsNone(self.sheet.clearPrintArea())

    def test_setNamedRange(self):
        self.assertTrue(self.sheet.setNamedRange("foo", 0, 10, 0, 10))
        self.assertEqual(1, self.sheet.namedRangeSize())
        self.assertEqual( ("foo", 0, 10, 0, 10), self.sheet.namedRange(0) )

    def test_delNamedRange(self):
        self.assertFalse(self.sheet.delNamedRange('foo'))
        self.assertTrue(self.sheet.setNamedRange("foo", 0, 10, 0, 10))
        self.assertTrue(self.sheet.delNamedRange('foo'))
        self.assertEqual(0, self.sheet.namedRangeSize())

    def test_namedRangeSize(self):
        self.assertEqual(0, self.sheet.namedRangeSize())

    def test_namedRange(self):
        self.assertIsInstance(self.sheet.namedRange(0), tuple)
        self.assertIsInstance(self.sheet.namedRange(-10), tuple)
        self.assertIsInstance(self.sheet.namedRange(10), tuple)

    def test_setName(self):
        self.assertIsNone(self.sheet.setName('foo'))

    def test_protect(self):
        self.assertFalse(self.sheet.protect())

    def test_setProtect(self):
        self.sheet.setProtect(True)
        self.assertTrue(self.sheet.protect())

    def test_hidden(self):
        self.assertEqual( SHEETSTATE_VISIBLE, self.sheet.hidden() )

    def test_setHidden(self):
        self.assertFalse( self.sheet.setHidden( SHEETSTATE_HIDDEN) )
        self.assertTrue( self.sheet.setHidden( SHEETSTATE_VISIBLE) )
        self.assertFalse( self.sheet.setHidden( SHEETSTATE_VERYHIDDEN) )

    def test_getTopLeftView(self):
        self.assertEqual( (0, 0), self.sheet.getTopLeftView() )

    def test_addrToRowCol(self):
        self.assertEqual( (0, 0, 0, 0), self.sheet.addrToRowCol('$A$1'))
        self.assertEqual( (0, 0, 1, 1), self.sheet.addrToRowCol('A1'))
        self.assertEqual( (2, 2, 0, 0), self.sheet.addrToRowCol('$C$3'))
        self.assertEqual( (2, 2, 1, 1), self.sheet.addrToRowCol('C3'))

    def test_rowColToAddr(self):
        self.assertEqual('$A$1', self.sheet.rowColToAddr(0, 0, 0, 0))
        self.assertEqual('A1', self.sheet.rowColToAddr(0, 0, 1, 1))
        self.assertEqual('$C$3', self.sheet.rowColToAddr(2, 2, 0, 0))
        self.assertEqual('C3', self.sheet.rowColToAddr(2, 2, 1, 1))

if __name__ == '__main__':
    unittest.main()
