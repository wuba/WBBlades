#include <stdio.h>
#include "libxl.h"

int main()
{
    BookHandle book = xlCreateBook();
    if(book) 
    {	
        int i, f[6];
        FormatHandle format[6];
        SheetHandle sheet;		

        f[0] = xlBookAddCustomNumFormat(book, "0.0");
        f[1] = xlBookAddCustomNumFormat(book, "0.00");
        f[2] = xlBookAddCustomNumFormat(book, "0.000");
        f[3] = xlBookAddCustomNumFormat(book, "0.0000");
        f[4] = xlBookAddCustomNumFormat(book, "#,###.00 $");
        f[5] = xlBookAddCustomNumFormat(book, "#,###.00 $[Black][<1000];#,###.00 $[Red][>=1000]");

        for(i = 0; i < 6; ++i) {
            format[i] = xlBookAddFormat(book, 0);
            xlFormatSetNumFormat(format[i], f[i]);
        }
	
        sheet = xlBookAddSheet(book, "Custom formats", 0);
        if(sheet) 
        {
            xlSheetSetCol(sheet, 0, 0, 20, 0, 0);
            xlSheetWriteNum(sheet, 2, 0, 25.718, format[0]);
            xlSheetWriteNum(sheet, 3, 0, 25.718, format[1]);
            xlSheetWriteNum(sheet, 4, 0, 25.718, format[2]);
            xlSheetWriteNum(sheet, 5, 0, 25.718, format[3]);

            xlSheetWriteNum(sheet, 7, 0, 1800.5, format[4]);

            xlSheetWriteNum(sheet, 9, 0, 500, format[5]);
            xlSheetWriteNum(sheet, 10, 0, 1600, format[5]);            
        }

        if(xlBookSave(book, "custom.xls")) printf("File custom.xls has been created.\n");
        xlBookRelease(book);
    }

    return 0;
}
