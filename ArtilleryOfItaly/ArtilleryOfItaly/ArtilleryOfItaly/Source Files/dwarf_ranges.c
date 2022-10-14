/*
  Copyright (C) 2008-2020 David Anderson. All Rights Reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

  This program is free software; you can redistribute it
  and/or modify it under the terms of version 2.1 of the
  GNU Lesser General Public License as published by the Free
  Software Foundation.

  This program is distributed in the hope that it would be
  useful, but WITHOUT ANY WARRANTY; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.

  Further, this software is distributed without any warranty
  that it is free of the rightful claim of any third person
  regarding infringement or the like.  Any license provided
  herein, whether implied or otherwise, applies only to this
  software file.  Patent licenses, if any, provided herein
  do not apply to combinations of this program with other
  software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General
  Public License along with this program; if not, write the
  Free Software Foundation, Inc., 51 Franklin Street - Fifth
  Floor, Boston MA 02110-1301, USA.

*/

#include <config.h>

#include <stdlib.h> /* calloc() free() */

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

struct ranges_entry {
    struct ranges_entry *next;
    Dwarf_Ranges cur;
};

static void
free_allocated_ranges( struct ranges_entry *base)
{
    struct ranges_entry *cur = 0;
    struct ranges_entry *next = 0;
    for ( cur = base ; cur ; cur = next ) {
        next = cur->next;
        free(cur);
    }
}

/*  We encapsulate the macro use so we can
    free local malloc resources that would otherwise
    leak. See the call points below. */
static int
read_unaligned_addr_check(Dwarf_Debug dbg,
    Dwarf_Addr *addr_out,
    Dwarf_Small *rangeptr,
    unsigned address_size,
    Dwarf_Error *error,
    Dwarf_Small *section_end)
{
    Dwarf_Addr a = 0;

    READ_UNALIGNED_CK(dbg,a,
        Dwarf_Addr, rangeptr,
        address_size,
        error,section_end);
    *addr_out = a;
    return DW_DLV_OK;
}
/*  As of DWARF5 the ranges section each range list set has
    a range-list-table header. See "7.28 Range List Table"
    in the DWARF5 standard.
    For DWARF5 the offset should be the offset of
    the range-list-table-header for that range list.
    For DWARF3 and DWARF4 the offset has to be that
    of a range list.
*/
/*  Ranges and pc values can be in a split dwarf object.
    In that case the appropriate values need to be
    incremented by data from the executable in
    the compilation unit with the same dwo_id.

    We return an error which is on the incoming dbg, not
    the possibly-tied-dbg localdbg.
    If incoming die is NULL there is no context, so do not look
    for a tied file, and address_size is the size
    of the overall object, not the address_size of the context. */
#define MAX_ADDR ((address_size == 8)? \
    0xffffffffffffffffULL:0xffffffff)
/*  New 10 September 2020 to accommodate the
    GNU extension of DWARF4 split-dwarf.
    The actual_offset field is set by the function
    to the actual final offset of the ranges
    in the separate tied (a.out) file. */
int dwarf_get_ranges_b(Dwarf_Debug dbg,
    Dwarf_Off rangesoffset,
    Dwarf_Die die,
    Dwarf_Off *actual_offset,
    Dwarf_Ranges ** rangesbuf,
    Dwarf_Signed * listlen,
    Dwarf_Unsigned * bytecount,
    Dwarf_Error * error)
{
    Dwarf_Small *rangeptr = 0;
    Dwarf_Small *beginrangeptr = 0;
    Dwarf_Small *section_end = 0;
    unsigned entry_count = 0;
    struct ranges_entry *base = 0;
    struct ranges_entry *last = 0;
    struct ranges_entry *curre = 0;
    Dwarf_Ranges * ranges_data_out = 0;
    unsigned copyindex = 0;
    Dwarf_Half address_size = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Unsigned ranges_base = 0;
    Dwarf_Debug localdbg = dbg;
    Dwarf_Error localerror = 0;
    Dwarf_Half die_version = 3; /* default for dwarf_get_ranges() */
    Dwarf_Half offset_size UNUSEDARG = 4;
    Dwarf_CU_Context cucontext = 0;
    Dwarf_Bool rangeslocal = TRUE;

    if (!dbg) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    address_size = localdbg->de_pointer_size; /* default  */
    if (die) {
        /*  If we wind up using the tied file the die_version
            had better match! It cannot be other than a match. */
        /*  Can return DW_DLV_ERROR, not DW_DLV_NO_ENTRY.
            Add err code if error.  Version comes from the
            cu context, not the DIE itself. */
        res = dwarf_get_version_of_die(die,&die_version,
            &offset_size);
        if (res == DW_DLV_ERROR) {
            _dwarf_error(dbg, error, DW_DLE_DIE_NO_CU_CONTEXT);
            return DW_DLV_ERROR;
        }
        if (!die->di_cu_context) {
            _dwarf_error(dbg, error, DW_DLE_DIE_NO_CU_CONTEXT);
            return DW_DLV_ERROR;
        }
        cucontext = die->di_cu_context;
        /*  The DW4 ranges base was never used in GNU
            but did get emitted, the note says, but
            the note is probably obsolete (so, now wrong).
            http://llvm.1065342.n5.nabble.com/DebugInfo\
            -DW-AT-GNU-ranges-base-in-non-fission-\
            td64194.html
            */
        /* ranges_base was merged from tied context. */
        ranges_base = cucontext->cc_ranges_base;
        address_size = cucontext->cc_address_size;
    }

    localdbg = dbg;
    res = _dwarf_load_section(localdbg, &localdbg->de_debug_ranges,
        error);
    if (res == DW_DLV_ERROR) {
        return res;
    }
    if (res == DW_DLV_NO_ENTRY) {
        /* data is in a.out, not dwp */
        localdbg = dbg->de_tied_data.td_tied_object;
        if (!localdbg) {
            return DW_DLV_NO_ENTRY;
        }
        res = _dwarf_load_section(localdbg,
            &localdbg->de_debug_ranges, &localerror);
        if (res == DW_DLV_ERROR) {
            _dwarf_error_mv_s_to_t(localdbg,&localerror,dbg,error);
            return res;
        }
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        rangeslocal = FALSE;
    }

    /*  Be safe in case adding rangesoffset and rangebase
        overflows. */
    if (rangesoffset  >= localdbg->de_debug_ranges.dss_size) {
        /* Documented behavior in libdwarf2.1.mm */
        return DW_DLV_NO_ENTRY;
    }
    if (ranges_base >= localdbg->de_debug_ranges.dss_size) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
            " ranges base is 0x%lx ",ranges_base);
        dwarfstring_append_printf_u(&m,
            " and section size is 0x%lx.",
            localdbg->de_debug_ranges.dss_size);
        _dwarf_error_string(dbg, error,
            DW_DLE_DEBUG_RANGES_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    if (!rangeslocal && ((rangesoffset +ranges_base) >=
        localdbg->de_debug_ranges.dss_size)) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
            " ranges base+offset  is 0x%lx ",
            ranges_base+rangesoffset);
        dwarfstring_append_printf_u(&m,
            " and section size is 0x%lx.",
            localdbg->de_debug_ranges.dss_size);
        _dwarf_error_string(dbg, error,
            DW_DLE_DEBUG_RANGES_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }

    /*  tied address_size must match the dwo address_size */
    section_end = localdbg->de_debug_ranges.dss_data +
        localdbg->de_debug_ranges.dss_size;
    rangeptr = localdbg->de_debug_ranges.dss_data;
    if (!rangeslocal) {
        /* printing ranges where range source is dwp,
            here we just assume present. */
        rangesoffset += ranges_base;
    }
    rangeptr += rangesoffset;
    beginrangeptr = rangeptr;

    for (;;) {
        struct ranges_entry * re = 0;

        if (rangeptr == section_end) {
            break;
        }
        if (rangeptr  > section_end) {
            dwarfstring m;

            free_allocated_ranges(base);
            dwarfstring_constructor(&m);
            dwarfstring_append(&m,
                "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
                " ranges pointer ran off the end "
                "of the  section");
            _dwarf_error_string(dbg, error,
                DW_DLE_DEBUG_RANGES_OFFSET_BAD,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        re = calloc(sizeof(struct ranges_entry),1);
        if (!re) {
            free_allocated_ranges(base);
            _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
            return DW_DLV_ERROR;
        }
        if ((rangeptr + (2*address_size)) > section_end) {
            free(re);
            free_allocated_ranges(base);
            _dwarf_error_string(dbg, error,
                DW_DLE_DEBUG_RANGES_OFFSET_BAD,
                "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
                " Not at the end of the ranges section "
                " but there is not enough room in the section "
                " for the next ranges entry");
            return  DW_DLV_ERROR;
        }
        entry_count++;
        res = read_unaligned_addr_check(localdbg,&re->cur.dwr_addr1,
            rangeptr, address_size,error,section_end);
        if (res != DW_DLV_OK) {
            free(re);
            free_allocated_ranges(base);
            return res;
        }
        rangeptr +=  address_size;
        res = read_unaligned_addr_check(localdbg,&re->cur.dwr_addr2,
            rangeptr, address_size,error,section_end);
        if (res != DW_DLV_OK) {
            free(re);
            free_allocated_ranges(base);
            return res;
        }
        rangeptr +=  address_size;
        if (!base) {
            base = re;
            last = re;
        } else {
            last->next = re;
            last = re;
        }
        if (re->cur.dwr_addr1 == 0 && re->cur.dwr_addr2 == 0) {
            re->cur.dwr_type =  DW_RANGES_END;
            break;
        } else if (re->cur.dwr_addr1 == MAX_ADDR) {
            re->cur.dwr_type =  DW_RANGES_ADDRESS_SELECTION;
        } else {
            re->cur.dwr_type =  DW_RANGES_ENTRY;
        }
    }

    /* We return ranges on dbg, so use that to allocate. */
    ranges_data_out =   (Dwarf_Ranges *)
        _dwarf_get_alloc(dbg,DW_DLA_RANGES,entry_count);
    if (!ranges_data_out) {
        /* Error, apply to original, not local dbg. */
        free_allocated_ranges(base);
        _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
        return DW_DLV_ERROR;
    }
    curre = base;
    *rangesbuf = ranges_data_out;
    *listlen = entry_count;
    for (copyindex = 0; curre && (copyindex < entry_count);
        ++copyindex,++ranges_data_out,curre=curre->next) {
        *ranges_data_out = curre->cur;
    }
    /* ASSERT: curre == NULL */
    free_allocated_ranges(base);
    base = 0;
    /* Callers will often not care about the bytes used. */
    if (actual_offset) {
        *actual_offset = rangesoffset;
    }
    if (bytecount) {
        *bytecount = rangeptr - beginrangeptr;
    }
    return DW_DLV_OK;
}

void
dwarf_dealloc_ranges(Dwarf_Debug dbg, Dwarf_Ranges * rangesbuf,
    Dwarf_Signed rangecount UNUSEDARG)
{
    dwarf_dealloc(dbg,rangesbuf, DW_DLA_RANGES);
}
