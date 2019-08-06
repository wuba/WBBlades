#ifndef LIBXL_CPP_H
#define LIBXL_CPP_H

#define LIBXL_VERSION 0x03080500

#include "IBookT.h"
#include "ISheetT.h"
#include "IFormatT.h"
#include "IFontT.h"
#include "IAutoFilterT.h"
#include "IFilterColumnT.h"

namespace libxl {

    #ifdef _UNICODE
        typedef IBookT<wchar_t> Book;
        typedef ISheetT<wchar_t> Sheet;
        typedef IFormatT<wchar_t> Format;
        typedef IFontT<wchar_t> Font;
        typedef IAutoFilterT<wchar_t> AutoFilter;
        typedef IFilterColumnT<wchar_t> FilterColumn;
        #define xlCreateBook xlCreateBookW
        #define xlCreateXMLBook xlCreateXMLBookW
    #else
        typedef IBookT<char> Book;
        typedef ISheetT<char> Sheet;
        typedef IFormatT<char> Format;
        typedef IFontT<char> Font;
        typedef IAutoFilterT<char> AutoFilter;
        typedef IFilterColumnT<char> FilterColumn;
        #define xlCreateBook xlCreateBookA
        #define xlCreateXMLBook xlCreateXMLBookA
    #endif

}

#endif
