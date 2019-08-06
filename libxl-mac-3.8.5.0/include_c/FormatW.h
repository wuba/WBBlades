#ifndef LIBXL_FORMATW_H
#define LIBXL_FORMATW_H

#include <stddef.h>
#include "setup.h"
#include "handle.h"
#include "enum.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI FontHandle XLAPIENTRY xlFormatFontW(FormatHandle handle);
    XLAPI        int XLAPIENTRY xlFormatSetFontW(FormatHandle handle, FontHandle fontHandle);

    XLAPI        int XLAPIENTRY xlFormatNumFormatW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetNumFormatW(FormatHandle handle, int numFormat);

    XLAPI        int XLAPIENTRY xlFormatAlignHW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetAlignHW(FormatHandle handle, int align);

    XLAPI        int XLAPIENTRY xlFormatAlignVW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetAlignVW(FormatHandle handle, int align);

    XLAPI        int XLAPIENTRY xlFormatWrapW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetWrapW(FormatHandle handle, int wrap);

    XLAPI        int XLAPIENTRY xlFormatRotationW(FormatHandle handle);
    XLAPI        int XLAPIENTRY xlFormatSetRotationW(FormatHandle handle, int rotation);

    XLAPI        int XLAPIENTRY xlFormatIndentW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetIndentW(FormatHandle handle, int indent);

    XLAPI        int XLAPIENTRY xlFormatShrinkToFitW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetShrinkToFitW(FormatHandle handle, int shrinkToFit);

    XLAPI       void XLAPIENTRY xlFormatSetBorderW(FormatHandle handle, int style);
    XLAPI       void XLAPIENTRY xlFormatSetBorderColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderLeftW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderLeftW(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderRightW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderRightW(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderTopW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderTopW(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderBottomW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderBottomW(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderLeftColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderLeftColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderRightColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderRightColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderTopColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderTopColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderBottomColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderBottomColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalW(FormatHandle handle, int border);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalStyleW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalStyleW(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatFillPatternW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetFillPatternW(FormatHandle handle, int pattern);

    XLAPI        int XLAPIENTRY xlFormatPatternForegroundColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetPatternForegroundColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatPatternBackgroundColorW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetPatternBackgroundColorW(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatLockedW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetLockedW(FormatHandle handle, int locked);

    XLAPI        int XLAPIENTRY xlFormatHiddenW(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetHiddenW(FormatHandle handle, int hidden);

#ifdef __cplusplus
}
#endif

#endif
