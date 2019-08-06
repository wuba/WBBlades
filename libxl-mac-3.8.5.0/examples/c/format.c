#include <stdio.h>
#include "libxl.h"

int main()
{
    BookHandle book = xlCreateBook();
    if(book) 
    {
        FontHandle font;
        FormatHandle format;
        SheetHandle sheet;
        
        font = xlBookAddFont(book, 0);
        xlFontSetName(font, "Impact");
        xlFontSetSize(font, 36);

        format = xlBookAddFormat(book, NULL);
        xlFormatSetAlignH(format, ALIGNH_CENTER);
        xlFormatSetBorder(format, BORDERSTYLE_MEDIUMDASHDOTDOT);
        xlFormatSetBorderColor(format, COLOR_RED);
        xlFormatSetFont(format, font);

        sheet = xlBookAddSheet(book, "Custom", 0);
        if(sheet) 
        {
            xlSheetWriteStr(sheet, 2, 1, "Format", format);
            xlSheetSetCol(sheet, 1, 1, 25, 0, 0);
        }

        if(xlBookSave(book, "format.xls")) printf("File format.xls has been created.\n");
    }


    return 0;
}
