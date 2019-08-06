#ifndef LIBXL_AUTOFILTERA_H
#define LIBXL_AUTOFILTERA_H

#include "setup.h"
#include "handle.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI                int XLAPIENTRY xlAutoFilterGetRefA(AutoFilterHandle handle, int* rowFirst, int* rowLast, int* colFirst, int* colLast);
    XLAPI               void XLAPIENTRY xlAutoFilterSetRefA(AutoFilterHandle handle, int rowFirst, int rowLast, int colFirst, int colLast);

    XLAPI FilterColumnHandle XLAPIENTRY xlAutoFilterColumnA(AutoFilterHandle handle, int colId);

    XLAPI                int XLAPIENTRY xlAutoFilterColumnSizeA(AutoFilterHandle handle);
    XLAPI FilterColumnHandle XLAPIENTRY xlAutoFilterColumnByIndexA(AutoFilterHandle handle, int index);

    XLAPI                int XLAPIENTRY xlAutoFilterGetSortRangeA(AutoFilterHandle handle, int* rowFirst, int* rowLast, int* colFirst, int* colLast);

    XLAPI                int XLAPIENTRY xlAutoFilterGetSortA(AutoFilterHandle handle, int* columnIndex, int* descending);
    XLAPI                int XLAPIENTRY xlAutoFilterSetSortA(AutoFilterHandle handle, int columnIndex, int descending);


#ifdef __cplusplus
}
#endif

#endif
