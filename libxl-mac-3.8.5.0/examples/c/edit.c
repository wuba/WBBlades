#include <stdio.h>
#include "libxl.h"

int main()
{
    BookHandle book = xlCreateBook();
    if(book) 
    {        
        if(xlBookLoad(book, "example.xls")) 
        {
            SheetHandle sheet = xlBookGetSheet(book, 0);
            if(sheet)
            {                
                double d = xlSheetReadNum(sheet, 3, 1, 0);
                xlSheetWriteNum(sheet, 3, 1, d * 2, 0);
                xlSheetWriteStr(sheet, 4, 1, "new string", 0);     
            }

            if(xlBookSave(book, "example.xls")) printf("File example.xls has been modified.\n");
        } 

        xlBookRelease(book);
    }

    return 0;
}
