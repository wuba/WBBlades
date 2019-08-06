#include <iostream>
#include "libxl.h"

using namespace libxl;

int main() 
{	
    Book* book = xlCreateBook();
    if(book)
    {
        int f[6];

        f[0] = book->addCustomNumFormat("0.0");
        f[1] = book->addCustomNumFormat("0.00");
        f[2] = book->addCustomNumFormat("0.000");
        f[3] = book->addCustomNumFormat("0.0000");
        f[4] = book->addCustomNumFormat("#,###.00 $");
        f[5] = book->addCustomNumFormat("#,###.00 $[Black][<1000];#,###.00 $[Red][>=1000]");

        Format* format[6];
        for(int i = 0; i < 6; ++i) {
            format[i] = book->addFormat();
            format[i]->setNumFormat(f[i]);
        }

        Sheet* sheet = book->addSheet("Custom formats");
        if(sheet)
        {
            sheet->setCol(0, 0, 20);
            sheet->writeNum(2, 0, 25.718, format[0]);
            sheet->writeNum(3, 0, 25.718, format[1]);
            sheet->writeNum(4, 0, 25.718, format[2]);
            sheet->writeNum(5, 0, 25.718, format[3]);

            sheet->writeNum(7, 0, 1800.5, format[4]);

            sheet->writeNum(9, 0, 500, format[5]);
            sheet->writeNum(10, 0, 1600, format[5]);
        }

        if(book->save("custom.xls")) {
            std::cout << "File custom.xls has been created." << std::endl;
        }
        book->release();
    } 

    return 0;
}
