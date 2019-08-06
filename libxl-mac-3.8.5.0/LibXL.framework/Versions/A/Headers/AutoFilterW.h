#ifndef LIBXL_AUTOFILTERW_H
#define LIBXL_AUTOFILTERW_H

#include "setup.h"
#include "handle.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI                int XLAPIENTRY xlAutoFilterGetRefW(AutoFilterHandle handle, int* rowFirst, int* rowLast, int* colFirst, int* colLast);
    XLAPI               void XLAPIENTRY xlAutoFilterSetRefW(AutoFilterHandle handle, int rowFirst, int rowLast, int colFirst, int colLast);

    XLAPI FilterColumnHandle XLAPIENTRY xlAutoFilterColumnW(AutoFilterHandle handle, int colId);

    XLAPI                int XLAPIENTRY xlAutoFilterColumnSizeW(AutoFilterHandle handle);
    XLAPI FilterColumnHandle XLAPIENTRY xlAutoFilterColumnByIndexW(AutoFilterHandle handle, int index);

    XLAPI                int XLAPIENTRY xlAutoFilterGetSortRangeW(AutoFilterHandle handle, int* rowFirst, int* rowLast, int* colFirst, int* colLast);

    XLAPI                int XLAPIENTRY xlAutoFilterGetSortW(AutoFilterHandle handle, int* columnIndex, int* descending);
    XLAPI                int XLAPIENTRY xlAutoFilterSetSortW(AutoFilterHandle handle, int columnIndex, int descending);


#ifdef __cplusplus
}
#endif

#endif
