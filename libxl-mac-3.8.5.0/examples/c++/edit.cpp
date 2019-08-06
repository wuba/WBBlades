#include <iostream>
#include "libxl.h"

using namespace libxl;

int main() 
{
    Book* book = xlCreateBook();
    if(book) 
    {                
        if(book->load("example.xls"))
        {
            Sheet* sheet = book->getSheet(0);
            if(sheet) 
            {   
                double d = sheet->readNum(3, 1);
                sheet->writeNum(3, 1, d * 2);
                sheet->writeStr(5, 1, "new string");
            }
            if(book->save("example.xls")) {
                std::cout << "File example.xls has been modified." << std::endl;
            }
        }

        book->release();   
    }

    return 0;
}


