#ifndef LIBXL_FONTW_H
#define LIBXL_FONTW_H

#include <stddef.h>
#include "setup.h"
#include "handle.h"
#include "enum.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI            int XLAPIENTRY xlFontSizeW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetSizeW(FontHandle handle, int size);

    XLAPI            int XLAPIENTRY xlFontItalicW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetItalicW(FontHandle handle, int italic);

    XLAPI            int XLAPIENTRY xlFontStrikeOutW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetStrikeOutW(FontHandle handle, int strikeOut);

    XLAPI            int XLAPIENTRY xlFontColorW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetColorW(FontHandle handle, int color);

    XLAPI            int XLAPIENTRY xlFontBoldW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetBoldW(FontHandle handle, int bold);

    XLAPI            int XLAPIENTRY xlFontScriptW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetScriptW(FontHandle handle, int script);

    XLAPI            int XLAPIENTRY xlFontUnderlineW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetUnderlineW(FontHandle handle, int underline);

    XLAPI const wchar_t* XLAPIENTRY xlFontNameW(FontHandle handle);
    XLAPI           void XLAPIENTRY xlFontSetNameW(FontHandle handle, const wchar_t* name);

#ifdef __cplusplus
}
#endif

#endif
