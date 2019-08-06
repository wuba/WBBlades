#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <time.h>
#include "libxl.h"

using namespace libxl;
using namespace std;

const int maxRow = 20000;
const int maxCol = 256;

std::string makeString()
{
    unsigned n = 8;
    std::string s;    
    s.resize(n);

    for(unsigned i = 0; i < n; ++i) {
        s[i] = 0x61 + rand() % 26;        
    }

    return s;
}

void test(int number)
{
    cout << "---------------------------------" << endl;
    if(number == 1) {
        cout << "           strings               " << endl;
    } else {
        cout << "           numbers               " << endl;
    }
    cout << "---------------------------------" << endl;

    Book* book = xlCreateBook();
    if(book)
    {
        Sheet* sheet = book->addSheet("Sheet1");
        if(sheet)
        {
            cout << "writing " << (maxRow - 1) * maxCol << " cells... " << flush;
            clock_t t1 = clock();
            if(number == 1) {
                for (int row = 1; row < maxRow; ++row)
                {
                    for (int col = 0; col < maxCol; ++col)
                    {
                        sheet->writeStr(row, col, makeString().c_str());
                    }                        
                }
            } else {
                for (int row = 1; row < maxRow; ++row)
                {
                    for (int col = 0; col < maxCol; ++col)
                    {
                        sheet->writeNum(row, col, 1234);
                    }
                }      
            }
            cout << "ok" << endl;
            clock_t t2 = clock();
            double d = (double)(t2 - t1) / CLOCKS_PER_SEC;
            cout << "time: " << d << " sec" << endl;

            double n;
            if(d > 0) {
                n = (maxRow - 1) * maxCol / d;				
                cout << "speed: " << (int)n << " cells/sec" << endl;
            }
            cout << endl;

            cout << "saving... ";

            if(number == 1) {
                book->save("perfstr.xls");
            } else {
                book->save("perfnum.xls");
            }

            cout << "ok" << endl;
            clock_t t3 = clock();
            
            cout << "time: " << (double)(t3 - t2) / CLOCKS_PER_SEC << " sec\n" << endl;
            cout << "total time: " << (double)(t3 - t1) / CLOCKS_PER_SEC << " sec" << endl;

            d = (double)(t3 - t1) / CLOCKS_PER_SEC;
            if(d > 0) {
                n = (maxRow - 1) * maxCol / d;
                cout << "speed with saving on disk: " << (int)n << " cells/sec" << endl;			
            }
            cout << endl;
        }
        
        book->release();
    }	
}

int main() 
{	
    test(0);
    test(1);

    return 0;
}
