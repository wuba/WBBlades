import unittest
from libxlpy import *

class TestBook(unittest.TestCase):
    def setUp(self):
        self.book = Book()

    def test_load(self):
        self.assertTrue(
            self.book.load('./book.xls')
        )

        self.assertFalse(
            self.book.load('./unexisting_file')
        )

    def test_addSheet(self):
        sheet = self.book.addSheet('foo')
        self.assertEqual('XLPySheet', type(sheet).__name__)

    def test_getSheet(self):
        sheet = self.book.getSheet(0)
        self.assertIsNone(sheet)

        self.book.addSheet('foo')
        sheet = self.book.getSheet(0)
        self.assertEqual('XLPySheet', type(sheet).__name__)

    def test_sheetType(self):
       self.book.addSheet('foo')
       self.assertEqual(
               self.book.sheetType(0),
               SHEETTYPE_SHEET)

       self.assertEqual(
               self.book.sheetType(99),
               SHEETTYPE_UNKNOWN)

    def test_delSheet(self):
        self.book.addSheet('foo')
        self.book.addSheet('bar')
        self.assertIsNotNone(self.book.getSheet(1))
        self.book.delSheet(1)
        self.assertIsNone(self.book.getSheet(1))

    def test_sheetCount(self):
        self.assertEqual(0, self.book.sheetCount())
        self.book.addSheet('foo')
        self.assertEqual(1, self.book.sheetCount())

    def test_addFormat(self):
        fmt = self.book.addFormat()
        self.assertEqual('XLPyFormat', type(fmt).__name__)

    def test_addFont(self):
        fnt = self.book.addFont()
        self.assertEqual('XLPyFont', type(fnt).__name__)
   
    def test_addCustomNumFormat(self):
        index = self.book.addCustomNumFormat("fmt");
        self.assertIsNotNone(index)

        self.assertEqual('fmt',
                self.book.customNumFormat(index))

    def test_customNumFormat(self):
        self.assertIsNone(
                self.book.customNumFormat(0))

    def test_format(self):
        fmt = self.book.format(0)
        self.assertEqual('XLPyFormat', type(fmt).__name__)

    def test_formatSize(self):
        num = self.book.formatSize()
        self.book.addFormat()
        self.assertEqual(num + 1, self.book.formatSize())

    def test_activeSheet(self):
        index = self.book.activeSheet()
        self.assertEqual(index, 0)

    def test_setActiveSheet(self):
        self.book.setActiveSheet(10)
        self.assertEqual(0, self.book.activeSheet())

        sheet = self.book.addSheet('foo')
        sheet = self.book.addSheet('bar')
        sheet = self.book.addSheet('foobar')
        self.book.setActiveSheet(2)
        self.assertEqual(2, self.book.activeSheet())
        

    def test_pictureSize(self):
        self.assertEqual(0, self.book.pictureSize())
        index = self.book.addPicture("./logo.png")
        self.assertEqual(1, self.book.pictureSize())

    def test_getPicture(self):
        (t, img) = self.book.getPicture(0)
        self.assertEqual(255, t)
        
        index = self.book.addPicture("./logo.png")
        (t, img) = self.book.getPicture(index)
        self.assertEqual(0, t)

    def test_defaultFont(self):
        (name, size) = self.book.defaultFont()
        self.assertIsInstance(name, str)
        self.assertIsInstance(size, int)

    def test_setDefaultFont(self):
        name, size = "Mono", 14
        self.book.setDefaultFont(name, size)
        self.assertEqual(
                self.book.defaultFont(),
                (name, size))

    def test_font(self):
        font = self.book.font(0)
        self.assertEqual('XLPyFont', type(font).__name__)
        
        font = self.book.font(999) # invalid font index
        self.assertIsNone(font)

    def test_fontSize(self):
        # default value
        self.assertEqual(5,
                self.book.fontSize())

    def test_datePack(self):
        self.assertIsInstance(
                self.book.datePack(2000, 1, 1, 1, 0, 0, 0), float)

    def test_dateUnpack(self):
        pack = self.book.datePack(2000, 1, 1, 1, 0, 0, 0)
        unpack = self.book.dateUnpack(pack)
        self.assertEqual(unpack,
                (2000, 1, 1, 1, 0, 0, 0))

    def test_colorPack(self):
        self.assertIsInstance(
                self.book.colorPack(0, 0, 0), int)

    def test_colorUnpack(self):
        r, g, b = 0, 127, 255
        pack = self.book.colorPack(r, g, b)
        unpack = self.book.colorUnpack(pack)
        self.assertEqual(unpack, (r,g,b))

    def test_addPicture(self):
        index = self.book.addPicture("./logo.png")
        self.assertEqual(0, index)

    def test_addPicture2(self):
        f = open('./logo.png')
        index = self.book.addPicture2(f.read())
        self.assertEqual(0, index)
        self.assertEqual('ok', self.book.errorMessage())

        self.book.addPicture2('invalid image data')
        self.assertEqual('unknown picture format', self.book.errorMessage())

    def test_refR1C1(self):
        self.assertFalse(self.book.refR1C1())

    def test_setRefR1C1(self):
        self.book.setRefR1C1(True)
        self.assertTrue(self.book.refR1C1())

        self.book.setRefR1C1(False)
        self.assertFalse(self.book.refR1C1())

    def test_rgbMode(self):
        self.assertFalse(self.book.rgbMode())

    def test_setRgbMode(self):
        self.book.setRgbMode(True)
        self.assertTrue(self.book.rgbMode())
        
        self.book.setRgbMode(False)
        self.assertFalse(self.book.rgbMode())

    def test_biffVersion(self):
        self.assertIsInstance(self.book.biffVersion(), int)

    @unittest.skip("Not available on libxl")
    def test_IsDate1904(self):
        self.assertFalse(self.book.isDate1904())

    @unittest.skip("Not available on libxl")
    def test_setDate1904(self):
        self.assertIsNone(self.book.setDate1904(1))
        self.assertTrue(self.book.isDate1904())
        
        self.assertIsNone(self.book.setDate1904(0))
        self.assertFalse(self.book.isDate1904())

    def test_setKey(self):
        self.assertIsNone( self.book.setKey("foo", "bar") )

    def test_setLocale(self):
        self.assertTrue(self.book.setLocale("UTF-8"))
        self.assertFalse(self.book.setLocale("BadLocale"))

    def test_errorMessage(self):
        self.assertEqual('ok', self.book.errorMessage())

        # perform some bad op
        self.book.load('ThereIsNoSuchFile.xls')
        self.assertNotEqual('ok', self.book.errorMessage())

if __name__ == '__main__':
    unittest.main()
