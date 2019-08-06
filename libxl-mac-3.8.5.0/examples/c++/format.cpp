#include <iostream>
#include "libxl.h"

using namespace libxl;

int main() 
{    
    Book* book = xlCreateBook();
    if(book) 
    {         
        Font* font = book->addFont();
        font->setName("Impact");
        font->setSize(36);

        Format* format = book->addFormat();
        format->setAlignH(ALIGNH_CENTER);
        format->setBorder(BORDERSTYLE_MEDIUMDASHDOTDOT);
        format->setBorderColor(COLOR_RED);
        format->setFont(font);
	               
        Sheet* sheet = book->addSheet("Custom");
        if(sheet)
        {
            sheet->writeStr(2, 1, "Format", format);
            sheet->setCol(1, 1, 25);
        }

        if(book->save("format.xls")) {
            std::cout << "File format.xls has been created." << std::endl;
        }

        book->release();
    }

    return 0;
}

