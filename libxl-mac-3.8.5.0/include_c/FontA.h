#ifndef LIBXL_FONTA_H
#define LIBXL_FONTA_H

#include "setup.h"
#include "handle.h"
#include "enum.h"

#ifdef __cplusplus
extern "C"
{
#endif

    XLAPI         int XLAPIENTRY xlFontSizeA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetSizeA(FontHandle handle, int size);

    XLAPI         int XLAPIENTRY xlFontItalicA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetItalicA(FontHandle handle, int italic);

    XLAPI         int XLAPIENTRY xlFontStrikeOutA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetStrikeOutA(FontHandle handle, int strikeOut);

    XLAPI         int XLAPIENTRY xlFontColorA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetColorA(FontHandle handle, int color);

    XLAPI         int XLAPIENTRY xlFontBoldA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetBoldA(FontHandle handle, int bold);

    XLAPI         int XLAPIENTRY xlFontScriptA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetScriptA(FontHandle handle, int script);

    XLAPI         int XLAPIENTRY xlFontUnderlineA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetUnderlineA(FontHandle handle, int underline);

    XLAPI const char* XLAPIENTRY xlFontNameA(FontHandle handle);
    XLAPI        void XLAPIENTRY xlFontSetNameA(FontHandle handle, const char* name);

#ifdef __cplusplus
}
#endif

#endif
