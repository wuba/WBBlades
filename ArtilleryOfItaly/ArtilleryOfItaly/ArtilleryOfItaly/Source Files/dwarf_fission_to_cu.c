/*
    Copyright (C) 2018-2020 David Anderson. All Rights Reserved.

    This program is free software; you can redistribute it
    and/or modify it under the terms of version 2.1 of the
    GNU Lesser General Public License as published by the
    Free Software Foundation.

    This program is distributed in the hope that it would
    be useful, but WITHOUT ANY WARRANTY; without even the
    implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.

    Further, this software is distributed without any warranty
    that it is free of the rightful claim of any third person
    regarding infringement or the like.  Any license provided
    herein, whether implied or otherwise, applies only to
    this software file.  Patent licenses, if any, provided
    herein do not apply to combinations of this program with
    other software, or any other product whatsoever.

    You should have received a copy of the GNU Lesser General
    Public License along with this program; if not, write
    the Free Software Foundation, Inc., 51 Franklin Street -
    Fifth Floor, Boston MA 02110-1301, USA.
*/

#include <config.h>

#include <string.h> /* memset() */

#if defined(_WIN32) && defined(HAVE_STDAFX_H)
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"
#include "dwarf_base_types.h"
#include "dwarf_opaque.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_string.h"
#include "dwarf_str_offsets.h"
#include "dwarf_loc.h"
#include "dwarf_rnglists.h"

/*  ASSERT: dbg,cu_context, and fsd are non-NULL
    as the caller ensured that. */
static int
load_xu_loclists_into_cucontext(Dwarf_Debug dbg,
    Dwarf_CU_Context cu_context,
    struct Dwarf_Debug_Fission_Per_CU_s*fsd,
    int fsd_index,
    Dwarf_Error *error)
{
    Dwarf_Unsigned size = 0;
    Dwarf_Unsigned soff_hdroffset = 0;
    Dwarf_Unsigned soff_size = 0;
    struct Dwarf_Loclists_Context_s localcontxt;
    Dwarf_Loclists_Context buildhere = &localcontxt;
    Dwarf_Unsigned nextset = 0;
    int res = 0;

    if (!fsd) {
        _dwarf_error_string(dbg, error, DW_DLE_XU_TYPE_ARG_ERROR,
            "DW_DLE_XU_TYPE_ARG_ERROR: a required argument to"
            "load_xu_loclists_into_cucontext() is NULL");
        return DW_DLV_ERROR;
    }
    size = fsd->pcu_size[fsd_index];
    soff_hdroffset = fsd->pcu_offset[fsd_index];
    soff_size = dbg->de_debug_loclists.dss_size;
    if (!soff_size) {
        return DW_DLV_NO_ENTRY;
    }
    if (soff_hdroffset >= soff_size) {
        /*  Something is badly wrong. Ignore it here. */
        return DW_DLV_NO_ENTRY;
    }
    memset(buildhere,0,sizeof(localcontxt));
    res = _dwarf_internal_read_loclists_header(dbg,
        0,soff_size,
        dbg->de_debug_loclists.dss_data,
        dbg->de_debug_loclists.dss_data +soff_size,
        soff_hdroffset,
        buildhere,
        &nextset,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    cu_context->cc_loclists_base_present = TRUE;
    cu_context->cc_loclists_base_contr_size = size;
    cu_context->cc_loclists_base            =
        buildhere->lc_offsets_off_in_sect;
    return DW_DLV_OK;
}

/*  ASSERT: cc_str_offsets_base_present FALSE
    ASSERT: cc_str_offsets_header_length_present  FALSE
    ASSERT: dbg,cu_context, and fsd are non-NULL
    as the caller ensured that.
    If .debug_cu_index or
    .debug_tu_index is present it might help us find
    the offset for this CU's .debug_str_offsets.
*/
static int
load_xu_str_offsets_into_cucontext(Dwarf_Debug dbg,
    Dwarf_CU_Context cu_context,
    struct Dwarf_Debug_Fission_Per_CU_s*fsd,
    int fsd_index,
    Dwarf_Error *error )
{
    Dwarf_Small *soff_secptr = 0;
    Dwarf_Small *soff_hdrptr = 0;
    Dwarf_Unsigned soff_hdroffset = 0;
    Dwarf_Unsigned soff_size = 0;
    Dwarf_Small *soff_eptr = 0;
    int res = 0;

    res = _dwarf_load_section(dbg, &dbg->de_debug_str_offsets,
        error);
    if (res != DW_DLV_OK) {
        return res;
    }
    soff_hdroffset = fsd->pcu_offset[fsd_index];
    soff_secptr = dbg->de_debug_str_offsets.dss_data;
    soff_size = dbg->de_debug_str_offsets.dss_size;
    soff_eptr = soff_secptr + soff_size;
    soff_hdrptr = soff_secptr + soff_hdroffset;
    if (soff_hdroffset >= soff_size) {
        /*  Something is badly wrong. Ignore it here. */
        return DW_DLV_NO_ENTRY;
    }

    {
        Dwarf_Unsigned length = 0;
        Dwarf_Half     offset_size = 0;
        Dwarf_Half     extension_size = 0;
        Dwarf_Half     version = 0;
        Dwarf_Half     padding = 0;
        Dwarf_Unsigned header_length = 0;

        res =  _dwarf_read_str_offsets_header(dbg,
            soff_hdrptr,
            soff_size - soff_hdroffset,
            soff_eptr,
            cu_context,
            &length,&offset_size,
            &extension_size,&version,&padding,
            &header_length,
            error);
        if (res != DW_DLV_OK) {
            if (res == DW_DLV_ERROR) {
                dwarf_dealloc_error(dbg,*error);
                *error = 0;
            }
            res = DW_DLV_NO_ENTRY;
            return res;
        }
        cu_context->cc_str_offsets_base_present = TRUE;
        cu_context->cc_str_offsets_header_length_present = TRUE;
        cu_context->cc_str_offsets_header_offset = soff_hdroffset;
        cu_context->cc_str_offsets_base = soff_hdroffset +
            header_length;
        cu_context->cc_str_offsets_header_length = header_length;
        cu_context->cc_str_offsets_offset_size = offset_size;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

/*  ASSERT: dbg,cu_context, and fsd are non-NULL
    as the caller ensured that. */
static int
load_xu_debug_macro_into_cucontext(Dwarf_Debug dbg,
    Dwarf_CU_Context cu_context,
    struct Dwarf_Debug_Fission_Per_CU_s*fsd,
    int fsd_index,
    Dwarf_Error *error )
{
    Dwarf_Unsigned size = 0;
    Dwarf_Unsigned soff_hdroffset = 0;
    Dwarf_Unsigned soff_size = 0;
    int res = 0;

    res = _dwarf_load_section(dbg, &dbg->de_debug_macro,
        error);
    if (res != DW_DLV_OK) {
        return res;
    }
    size = fsd->pcu_size[fsd_index];
    soff_hdroffset = fsd->pcu_offset[fsd_index];
    soff_size = dbg->de_debug_macro.dss_size;
    if (!soff_size) {
        return DW_DLV_NO_ENTRY;
    }
    if (soff_hdroffset >= soff_size) {
        /*  Something is badly wrong. Ignore it here. */
        return DW_DLV_NO_ENTRY;
    }
    /*  Presently assuming that DW_AT_macros
        and the fission entry both
        indicate the beginning
        of a .debug_macro sectiom macro header.
        (not true for str_offsets or for loclists!)
    */
    cu_context->cc_macro_base_present = TRUE;
    cu_context->cc_macro_base_contr_size = size;
    cu_context->cc_macro_base            = soff_hdroffset;
    /* FIXME cc_macro_header_length_present? */
    return DW_DLV_OK;
}

/*  ASSERT: dbg,cu_context, and fsd are non-NULL
    as the caller ensured that. */
static int
load_xu_rnglists_into_cucontext(Dwarf_Debug dbg,
    Dwarf_CU_Context cu_context,
    struct Dwarf_Debug_Fission_Per_CU_s*fsd,
    int fsd_index,
    Dwarf_Error *error )
{
    Dwarf_Unsigned size = 0;
    Dwarf_Unsigned soff_hdroffset = 0;
    Dwarf_Unsigned soff_size = 0;
    struct Dwarf_Rnglists_Context_s builddata;
    Dwarf_Rnglists_Context buildhere =  &builddata;
    Dwarf_Unsigned nextoffset = 0;
    int res = 0;

    res = _dwarf_load_section(dbg, &dbg->de_debug_rnglists,
        error);
    if (res != DW_DLV_OK) {
        return res;
    }
    size = fsd->pcu_size[fsd_index];
    soff_hdroffset = fsd->pcu_offset[fsd_index];
    soff_size = dbg->de_debug_rnglists.dss_size;
    if (!soff_size) {
        return DW_DLV_NO_ENTRY;
    }
    if (soff_hdroffset >= soff_size) {
        /*  Something is badly wrong. Ignore it here. */
        return DW_DLV_NO_ENTRY;
    }
    memset(buildhere,0,sizeof(builddata));
    res = _dwarf_internal_read_rnglists_header(dbg,
        0,soff_size,
        dbg->de_debug_rnglists.dss_data,
        dbg->de_debug_rnglists.dss_data+soff_size,
        soff_hdroffset,buildhere,
        &nextoffset,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    cu_context->cc_rnglists_base  =
        buildhere->rc_offsets_off_in_sect;
    cu_context->cc_rnglists_base_present = TRUE;
    cu_context->cc_rnglists_base_contr_size = size;
    /* FIXME cc_rnglists_header_length_present? */
    return DW_DLV_OK;
}

static const char *keylist[2] = {
"cu",
"tu"
};
/*  ASSERT: The context has a signature.

    ASSERT: dbg and cu_context are non-NULL
    as the caller tested them.

    _dwarf_make_CU_Context() calls
        finish_up_cu_context_from_cudie() which calls
        us here.
    Then, _dwarf_make_CU_Context() calls
    _dwarf_merge_all_base_attrs_of_cu_die() if there
    is a tied (executable) object known.

    Called by dwarf_die_deliv.c
*/
int
_dwarf_find_all_offsets_via_fission(Dwarf_Debug dbg,
    Dwarf_CU_Context cu_context,
    Dwarf_Error *error)
{
    struct Dwarf_Debug_Fission_Per_CU_s fission_data;
    struct Dwarf_Debug_Fission_Per_CU_s*fsd = 0;
    int si = 0;
    int smax = 2;
    int fdres = 0;
    int res = 0;

    fsd = &fission_data;
    for (si = 0; si < smax ; ++si) {
        int sec_index = 0;

        memset(&fission_data,0,sizeof(fission_data));
        fdres = dwarf_get_debugfission_for_key(dbg,
            &cu_context->cc_signature,
            keylist[si],
            fsd,error);
        if (fdres == DW_DLV_NO_ENTRY) {
            continue;
        }
        if (fdres == DW_DLV_ERROR) {
            dwarf_dealloc_error(dbg,*error);
            *error = 0;
            continue;
        }
        for (sec_index = 1; sec_index < DW_FISSION_SECT_COUNT;
            ++sec_index) {
            if (!fsd->pcu_size[sec_index]) {
                continue;
            }
            res = DW_DLV_OK;
            switch(sec_index) {
            /*  these handled elsewhere, such
                as by _dwarf_get_dwp_extra_offset()
                _dwarf_get_fission_addition_die()
            case DW_SECT_INFO:
            case DW_SECT_ABBREV:
            case DW_SECT_LINE:
            */
            case DW_SECT_LOCLISTS:
                res = load_xu_loclists_into_cucontext(dbg,
                    cu_context,
                    fsd,sec_index,error);
                break;
            case DW_SECT_STR_OFFSETS:
                res = load_xu_str_offsets_into_cucontext(dbg,
                    cu_context,
                    fsd,sec_index,error);
                break;
            case DW_SECT_MACRO:
                res = load_xu_debug_macro_into_cucontext(dbg,
                    cu_context,
                    fsd,sec_index,error);
                break;
            case DW_SECT_RNGLISTS:
                res = load_xu_rnglists_into_cucontext(dbg,
                    cu_context,
                    fsd,sec_index,error);
                break;
            default:
                res = DW_DLV_OK;
                break;
            }
            if (res == DW_DLV_ERROR) {
                return res;
            }
        }
    }
    return DW_DLV_OK;
}
