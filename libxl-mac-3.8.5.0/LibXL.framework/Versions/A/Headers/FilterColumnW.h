#ifndef LIBXL_FILTERCOLUMNW_H
#define LIBXL_FILTERCOLUMNW_H

#include "setup.h"
#include "handle.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI            int XLAPIENTRY xlFilterColumnIndexW(FilterColumnHandle handle);

    XLAPI            int XLAPIENTRY xlFilterColumnFilterTypeW(FilterColumnHandle handle);

    XLAPI            int XLAPIENTRY xlFilterColumnFilterSizeW(FilterColumnHandle handle);
    XLAPI const wchar_t* XLAPIENTRY xlFilterColumnFilterW(FilterColumnHandle handle, int index);
    XLAPI           void XLAPIENTRY xlFilterColumnAddFilterW(FilterColumnHandle handle, const wchar_t* value);

    XLAPI            int XLAPIENTRY xlFilterColumnGetTop10W(FilterColumnHandle handle, double* value, int* top, int* percent);
    XLAPI           void XLAPIENTRY xlFilterColumnSetTop10W(FilterColumnHandle handle, double value, int top, int percent);

    XLAPI            int XLAPIENTRY xlFilterColumnGetCustomFilterW(FilterColumnHandle handle, int* op1, const wchar_t** v1, int* op2, const wchar_t** v2, int* andOp);
    XLAPI           void XLAPIENTRY xlFilterColumnSetCustomFilterW(FilterColumnHandle handle, int op, const wchar_t* val);
    XLAPI           void XLAPIENTRY xlFilterColumnSetCustomFilterExW(FilterColumnHandle handle, int op1, const wchar_t* v1, int op2, const wchar_t* v2, int andOp);

    XLAPI           void XLAPIENTRY xlFilterColumnClearW(FilterColumnHandle handle);

#ifdef __cplusplus
}
#endif

#endif

