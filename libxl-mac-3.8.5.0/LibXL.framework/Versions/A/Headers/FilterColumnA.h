#ifndef LIBXL_FILTERCOLUMNA_H
#define LIBXL_FILTERCOLUMNA_H

#include "setup.h"
#include "handle.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI         int XLAPIENTRY xlFilterColumnIndexA(FilterColumnHandle handle);

    XLAPI         int XLAPIENTRY xlFilterColumnFilterTypeA(FilterColumnHandle handle);

    XLAPI         int XLAPIENTRY xlFilterColumnFilterSizeA(FilterColumnHandle handle);
    XLAPI const char* XLAPIENTRY xlFilterColumnFilterA(FilterColumnHandle handle, int index);
    XLAPI        void XLAPIENTRY xlFilterColumnAddFilterA(FilterColumnHandle handle, const char* value);

    XLAPI         int XLAPIENTRY xlFilterColumnGetTop10A(FilterColumnHandle handle, double* value, int* top, int* percent);
    XLAPI        void XLAPIENTRY xlFilterColumnSetTop10A(FilterColumnHandle handle, double value, int top, int percent);

    XLAPI         int XLAPIENTRY xlFilterColumnGetCustomFilterA(FilterColumnHandle handle, int* op1, const char** v1, int* op2, const char** v2, int* andOp);
    XLAPI        void XLAPIENTRY xlFilterColumnSetCustomFilterA(FilterColumnHandle handle, int op, const char* cond);
    XLAPI        void XLAPIENTRY xlFilterColumnSetCustomFilterExA(FilterColumnHandle handle, int op1, const char* v1, int op2, const char* v2, int andOp);

    XLAPI        void XLAPIENTRY xlFilterColumnClearA(FilterColumnHandle handle);

#ifdef __cplusplus
}
#endif

#endif

