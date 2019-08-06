#ifndef LIBXL_FORMATA_H
#define LIBXL_FORMATA_H

#include "setup.h"
#include "handle.h"
#include "enum.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI FontHandle XLAPIENTRY xlFormatFontA(FormatHandle handle);
    XLAPI        int XLAPIENTRY xlFormatSetFontA(FormatHandle handle, FontHandle fontHandle);

    XLAPI        int XLAPIENTRY xlFormatNumFormatA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetNumFormatA(FormatHandle handle, int numFormat);

    XLAPI        int XLAPIENTRY xlFormatAlignHA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetAlignHA(FormatHandle handle, int align);

    XLAPI        int XLAPIENTRY xlFormatAlignVA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetAlignVA(FormatHandle handle, int align);

    XLAPI        int XLAPIENTRY xlFormatWrapA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetWrapA(FormatHandle handle, int wrap);

    XLAPI        int XLAPIENTRY xlFormatRotationA(FormatHandle handle);
    XLAPI        int XLAPIENTRY xlFormatSetRotationA(FormatHandle handle, int rotation);

    XLAPI        int XLAPIENTRY xlFormatIndentA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetIndentA(FormatHandle handle, int indent);

    XLAPI        int XLAPIENTRY xlFormatShrinkToFitA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetShrinkToFitA(FormatHandle handle, int shrinkToFit);

    XLAPI       void XLAPIENTRY xlFormatSetBorderA(FormatHandle handle, int style);
    XLAPI       void XLAPIENTRY xlFormatSetBorderColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderLeftA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderLeftA(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderRightA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderRightA(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderTopA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderTopA(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderBottomA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderBottomA(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderLeftColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderLeftColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderRightColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderRightColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderTopColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderTopColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderBottomColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderBottomColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalA(FormatHandle handle, int border);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalStyleA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalStyleA(FormatHandle handle, int style);

    XLAPI        int XLAPIENTRY xlFormatBorderDiagonalColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetBorderDiagonalColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatFillPatternA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetFillPatternA(FormatHandle handle, int pattern);

    XLAPI        int XLAPIENTRY xlFormatPatternForegroundColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetPatternForegroundColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatPatternBackgroundColorA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetPatternBackgroundColorA(FormatHandle handle, int color);

    XLAPI        int XLAPIENTRY xlFormatLockedA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetLockedA(FormatHandle handle, int locked);

    XLAPI        int XLAPIENTRY xlFormatHiddenA(FormatHandle handle);
    XLAPI       void XLAPIENTRY xlFormatSetHiddenA(FormatHandle handle, int hidden);

#ifdef __cplusplus
}
#endif

#endif
