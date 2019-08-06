#include <stdio.h>
#include "libxl.h"

int main()
{
    BookHandle book = xlCreateXMLBook();
    if(book) 
    {   
        FontHandle boldFont;
        FontHandle titleFont;
        FormatHandle titleFormat;
        FormatHandle headerFormat;
        FormatHandle descriptionFormat;
        FormatHandle amountFormat;
        FormatHandle totalLabelFormat;
        FormatHandle totalFormat;
        FormatHandle signatureFormat;
        SheetHandle sheet;
      
        boldFont = xlBookAddFont(book, 0);
        xlFontSetBold(boldFont, 1);

        titleFont = xlBookAddFont(book, 0);
        xlFontSetName(titleFont, "Arial Black");
        xlFontSetSize(titleFont, 16);

        titleFormat = xlBookAddFormat(book, 0);
        xlFormatSetFont(titleFormat, titleFont);

        headerFormat = xlBookAddFormat(book, 0);
        xlFormatSetAlignH(headerFormat, ALIGNH_CENTER);
        xlFormatSetBorder(headerFormat, BORDERSTYLE_THIN);
        xlFormatSetFont(headerFormat, boldFont);        
        xlFormatSetFillPattern(headerFormat, FILLPATTERN_SOLID);
        xlFormatSetPatternForegroundColor(headerFormat, COLOR_TAN);

        descriptionFormat = xlBookAddFormat(book, 0);
        xlFormatSetBorderLeft(descriptionFormat, BORDERSTYLE_THIN);

        amountFormat = xlBookAddFormat(book, 0);
        xlFormatSetNumFormat(amountFormat, NUMFORMAT_CURRENCY_NEGBRA);
        xlFormatSetBorderLeft(amountFormat, BORDERSTYLE_THIN);
        xlFormatSetBorderRight(amountFormat, BORDERSTYLE_THIN);
                
        totalLabelFormat = xlBookAddFormat(book, 0);
        xlFormatSetBorderTop(totalLabelFormat, BORDERSTYLE_THIN);
        xlFormatSetAlignH(totalLabelFormat, ALIGNH_RIGHT);
        xlFormatSetFont(totalLabelFormat, boldFont);

        totalFormat = xlBookAddFormat(book, 0);
        xlFormatSetNumFormat(totalFormat, NUMFORMAT_CURRENCY_NEGBRA);
        xlFormatSetBorder(totalFormat, BORDERSTYLE_THIN);
        xlFormatSetFont(totalFormat, boldFont);
        xlFormatSetFillPattern(totalFormat, FILLPATTERN_SOLID);
        xlFormatSetPatternForegroundColor(totalFormat, COLOR_YELLOW);

        signatureFormat = xlBookAddFormat(book, 0);
        xlFormatSetAlignH(signatureFormat, ALIGNH_CENTER);
        xlFormatSetBorderTop(signatureFormat, BORDERSTYLE_THIN);
             
        sheet = xlBookAddSheet(book, "Invoice", 0);
        if(sheet)
        {
            xlSheetWriteStr(sheet, 2, 1, "Invoice No. 3568", titleFormat);

            xlSheetWriteStr(sheet, 4, 1, "Name: John Smith", NULL);
            xlSheetWriteStr(sheet, 5, 1, "Address: San Ramon, CA 94583 USA", 0);

            xlSheetWriteStr(sheet, 7, 1, "Description", headerFormat);
            xlSheetWriteStr(sheet, 7, 2, "Amount", headerFormat);

            xlSheetWriteStr(sheet, 8, 1, "Ball-Point Pens", descriptionFormat);
            xlSheetWriteNum(sheet, 8, 2, 85, amountFormat);
            xlSheetWriteStr(sheet, 9, 1, "T-Shirts", descriptionFormat);
            xlSheetWriteNum(sheet, 9, 2, 150, amountFormat);
            xlSheetWriteStr(sheet, 10, 1, "Tea cups", descriptionFormat);
            xlSheetWriteNum(sheet, 10, 2, 45, amountFormat);

            xlSheetWriteStr(sheet, 11, 1, "Total:", totalLabelFormat);
            xlSheetWriteFormula(sheet, 11, 2, "=SUM(C9:C11)", totalFormat);

            xlSheetWriteStr(sheet, 14, 2, "Signature", signatureFormat);

            xlSheetSetCol(sheet, 1, 1, 40, 0, 0);
            xlSheetSetCol(sheet, 2, 2, 15, 0, 0);
        }

        if(xlBookSave(book, "invoice.xlsx")) printf("File invoice.xlsx has been created.\n");
        xlBookRelease(book);   
    }

    return 0;
}
