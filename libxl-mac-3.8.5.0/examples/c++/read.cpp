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
                const char* s = sheet->readStr(2, 1);
                if(s) std::cout << s << std::endl; 

                double d = sheet->readNum(3, 1);                
                std::cout << d << std::endl;

                int year, month, day;
                book->dateUnpack(sheet->readNum(4, 1), &year, &month, &day);
                std::cout << year << "-" << month << "-" << day << std::endl;
            }
        }
        
        book->release();
    }
    
    return 0;
}
