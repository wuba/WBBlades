#ifndef LIBXL_BOOKA_H
#define LIBXL_BOOKA_H

#include <stddef.h>
#include "setup.h"
#include "handle.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI     BookHandle XLAPIENTRY xlCreateBookCA(void);
    XLAPI     BookHandle XLAPIENTRY xlCreateXMLBookCA(void);

    XLAPI            int XLAPIENTRY xlBookLoadA(BookHandle handle, const char* filename);
    XLAPI            int XLAPIENTRY xlBookSaveA(BookHandle handle, const char* filename);

    XLAPI            int XLAPIENTRY xlBookLoadUsingTempFileA(BookHandle handle, const char* filename, const char* tempFile);
    XLAPI            int XLAPIENTRY xlBookSaveUsingTempFileA(BookHandle handle, const char* filename, int useTempFile);

    XLAPI            int XLAPIENTRY xlBookLoadPartiallyA(BookHandle handle, const char* filename, int sheetIndex, int firstRow, int lastRow);
    XLAPI            int XLAPIENTRY xlBookLoadPartiallyUsingTempFileA(BookHandle handle, const char* filename, int sheetIndex, int firstRow, int lastRow, const char* tempFile);

    XLAPI            int XLAPIENTRY xlBookLoadWithoutEmptyCellsA(BookHandle handle, const char* filename);
    XLAPI            int XLAPIENTRY xlBookLoadInfoA(BookHandle handle, const char* filename);

    XLAPI            int XLAPIENTRY xlBookLoadRawA(BookHandle handle, const char* data, unsigned size);
    XLAPI            int XLAPIENTRY xlBookLoadRawPartiallyA(BookHandle handle, const char* data, unsigned size, int sheetIndex, int firstRow, int lastRow);
    XLAPI            int XLAPIENTRY xlBookSaveRawA(BookHandle handle, const char** data, unsigned* size);

    XLAPI    SheetHandle XLAPIENTRY xlBookAddSheetA(BookHandle handle, const char* name, SheetHandle initSheet);
    XLAPI    SheetHandle XLAPIENTRY xlBookInsertSheetA(BookHandle handle, int index, const char* name, SheetHandle initSheet);
    XLAPI    SheetHandle XLAPIENTRY xlBookGetSheetA(BookHandle handle, int index);
    XLAPI    const char* XLAPIENTRY xlBookGetSheetNameA(BookHandle handle, int index);
    XLAPI            int XLAPIENTRY xlBookSheetTypeA(BookHandle handle, int index);
    XLAPI            int XLAPIENTRY xlBookMoveSheetA(BookHandle handle, int srcIndex, int dstIndex);
    XLAPI            int XLAPIENTRY xlBookDelSheetA(BookHandle handle, int index);
    XLAPI            int XLAPIENTRY xlBookSheetCountA(BookHandle handle);

    XLAPI   FormatHandle XLAPIENTRY xlBookAddFormatA(BookHandle handle, FormatHandle initFormat);
    XLAPI     FontHandle XLAPIENTRY xlBookAddFontA(BookHandle handle, FontHandle initFont);
    XLAPI            int XLAPIENTRY xlBookAddCustomNumFormatA(BookHandle handle, const char* customNumFormat);
    XLAPI    const char* XLAPIENTRY xlBookCustomNumFormatA(BookHandle handle, int fmt);

    XLAPI   FormatHandle XLAPIENTRY xlBookFormatA(BookHandle handle, int index);
    XLAPI            int XLAPIENTRY xlBookFormatSizeA(BookHandle handle);

    XLAPI     FontHandle XLAPIENTRY xlBookFontA(BookHandle handle, int index);
    XLAPI            int XLAPIENTRY xlBookFontSizeA(BookHandle handle);

    XLAPI         double XLAPIENTRY xlBookDatePackA(BookHandle handle, int year, int month, int day, int hour, int min, int sec, int msec);
    XLAPI            int XLAPIENTRY xlBookDateUnpackA(BookHandle handle, double value, int* year, int* month, int* day, int* hour, int* min, int* sec, int* msec);

    XLAPI            int XLAPIENTRY xlBookColorPackA(BookHandle handle, int red, int green, int blue);
    XLAPI           void XLAPIENTRY xlBookColorUnpackA(BookHandle handle, int color, int* red, int* green, int* blue);

    XLAPI            int XLAPIENTRY xlBookActiveSheetA(BookHandle handle);
    XLAPI           void XLAPIENTRY xlBookSetActiveSheetA(BookHandle handle, int index);

    XLAPI            int XLAPIENTRY xlBookPictureSizeA(BookHandle handle);
    XLAPI            int XLAPIENTRY xlBookGetPictureA(BookHandle handle, int index, const char** data, unsigned* size);

    XLAPI            int XLAPIENTRY xlBookAddPictureA(BookHandle handle, const char* filename);
    XLAPI            int XLAPIENTRY xlBookAddPicture2A(BookHandle handle, const char* data, unsigned size);
    XLAPI            int XLAPIENTRY xlBookAddPictureAsLinkA(BookHandle handle, const char* filename, int insert);

    XLAPI    const char* XLAPIENTRY xlBookDefaultFontA(BookHandle handle, int* fontSize);
    XLAPI           void XLAPIENTRY xlBookSetDefaultFontA(BookHandle handle, const char* fontName, int fontSize);

    XLAPI            int XLAPIENTRY xlBookRefR1C1A(BookHandle handle);
    XLAPI           void XLAPIENTRY xlBookSetRefR1C1A(BookHandle handle, int refR1C1);

    XLAPI           void XLAPIENTRY xlBookSetKeyA(BookHandle handle, const char* name, const char* key);

    XLAPI            int XLAPIENTRY xlBookRgbModeA(BookHandle handle);
    XLAPI           void XLAPIENTRY xlBookSetRgbModeA(BookHandle handle, int rgbMode);

    XLAPI            int XLAPIENTRY xlBookVersionA(BookHandle handle);
    XLAPI            int XLAPIENTRY xlBookBiffVersionA(BookHandle handle);

    XLAPI            int XLAPIENTRY xlBookIsDate1904A(BookHandle handle);
    XLAPI           void XLAPIENTRY xlBookSetDate1904A(BookHandle handle, int date1904);

    XLAPI            int XLAPIENTRY xlBookIsTemplateA(BookHandle handle);
    XLAPI           void XLAPIENTRY xlBookSetTemplateA(BookHandle handle, int tmpl);

    XLAPI            int XLAPIENTRY xlBookSetLocaleA(BookHandle handle, const char* locale);
    XLAPI    const char* XLAPIENTRY xlBookErrorMessageA(BookHandle handle);

    XLAPI           void XLAPIENTRY xlBookReleaseA(BookHandle handle);

#ifdef __cplusplus
}
#endif

#endif
