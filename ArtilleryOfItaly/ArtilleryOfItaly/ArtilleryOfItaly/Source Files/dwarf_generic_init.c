/*
  Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All rights reserved.
  Portions Copyright 2011-2020 David Anderson. All rights reserved.
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
/*
Here is the deepest routes through dwarf_init_path_dl(),
depending on arguments.
It is called by dwarfdump to open an fd and return Dwarf_Debug.
Much of this is to handle GNU debuglink.
dwarf_init_path_dl(path true_path and globals, dbg1
    dwarf_object_detector_path_dSYM (dsym only(
        if returns DW_DLV_OK itis dSYM
    dwarf_object_detector_path_b( &debuglink with global paths.
        dwarf_object_detector_path_b  ftype
            check for dSYM if found it is the object to run on.
                dwarf_object_detector_fd (gets size ftype)
                return
            _dwarf_debuglink_finder_internal(TRUE passing
                in globals paths listr)
                new local dbg
                dwarf_init_path(path no dysm or debuglink
                    no global paths)
                    dwarf_object_detector_path_b( path  no dsym
                        or debuglink no global paths
                        dwarf_object_detector (path
                        dwarf_object_detector_fd (gets size ftype)
                    for each global pathin list, add to dbg
                    dwarf_gnu_debuglink(dbg
                        for each global path in debuglink list
                            _dwarf_debuglink_finder_internal(FALSE
                                no global paths)
                                if crc match return OK with
                                    pathname and fd returned
                                else return NO_ENTRY
*/

#include <config.h>

#include <stddef.h> /* size_t */
#include <stdlib.h> /* free() */
#include <string.h> /* strdup() */

#ifdef _WIN32
#ifdef HAVE_STDAFX_H
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */
#include <io.h> /* close() open() */
#elif defined HAVE_UNISTD_H
#include <unistd.h> /* close() */
#endif /* _WIN32 */

#ifdef HAVE_FCNTL_H
#include <fcntl.h> /* open() O_RDONLY */
#endif /* HAVE_FCNTL_H */

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"
#include "dwarf_base_types.h"
#include "dwarf_opaque.h"
#include "dwarf_error.h"
#include "dwarf_object_detector.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif /* O_BINARY */

/*  This is the initialization set intended to
    handle multiple object formats.
    Created September 2018

    The init functions here cannot process archives.
    Archives cannot be read by libdwarf.
*/
static int
open_a_file(const char * name)
{
    /* Set to a file number that cannot be legal. */
    int fd = -1;

    fd = open(name, O_RDONLY | O_BINARY);
    return fd;
}

static int
set_global_paths_init(Dwarf_Debug dbg, Dwarf_Error* error)
{
    int res = 0;

    res = dwarf_add_debuglink_global_path(dbg,
        "/usr/lib/debug",error);
    return res;
}

/* New in December 2018. */
int dwarf_init_path(const char *path,
    char            * true_path_out_buffer,
    unsigned          true_path_bufferlen,
    unsigned          groupnumber,
    Dwarf_Handler     errhand,
    Dwarf_Ptr         errarg,
    Dwarf_Debug     * ret_dbg,
    Dwarf_Error     * error)
{
    return dwarf_init_path_dl(path,
        true_path_out_buffer,true_path_bufferlen,
        groupnumber,errhand,errarg,ret_dbg,
        0,0,0,
        error);
}

static void
final_common_settings(Dwarf_Debug dbg,
    const char *file_path,
    int fd,
    unsigned char lpath_source,
    unsigned char *path_source,
    Dwarf_Error *error)
{
    int res = 0;

    dbg->de_path = strdup(file_path);
    dbg->de_fd = fd;
    dbg->de_owns_fd = TRUE;
    dbg->de_path_source = lpath_source;
    if (path_source) {
        *path_source = lpath_source;
    }
    dbg->de_owns_fd = TRUE;
    res = set_global_paths_init(dbg,error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc_error(dbg,*error);
        *error = 0;
    }
    return;
}
/*  New October 2020
    Given true_path_out_buffer (and true_path_bufferlen)
    non-zero this finds a dSYM (if such exists) with the
    file name in true_path_out_buffer

    If not a dSYM it follows debuglink rules to try to find a file
    that matches requirements. If found returns DW_DLV_OK and
    copies the name to true_path_out_buffer;
    If none of the above found, it copies path into true_path
    and returns DW_DLV_OK, we know the name is good;

    The pathn_fd is owned by libdwarf and is in the created dbg->de_fd
    field.
*/
int
dwarf_init_path_dl(const char *path,
    char            * true_path_out_buffer,
    unsigned        true_path_bufferlen,
    unsigned        groupnumber,
    Dwarf_Handler   errhand,
    Dwarf_Ptr       errarg,
    Dwarf_Debug     * ret_dbg,
    char            ** dl_path_array,
    unsigned int    dl_path_count,
    unsigned char   * path_source,
    Dwarf_Error     * error)
{
    unsigned       ftype = 0;
    unsigned       endian = 0;
    unsigned       offsetsize = 0;
    Dwarf_Unsigned filesize = 0;
    int res =  DW_DLV_ERROR;
    int errcode = 0;
    int fd = -1;
    Dwarf_Debug dbg = 0;
    char *file_path = 0;
    unsigned char  lpath_source = DW_PATHSOURCE_basic;

    if (!ret_dbg) {
        DWARF_DBG_ERROR(NULL,DW_DLE_DWARF_INIT_DBG_NULL,
            DW_DLV_ERROR);
    }
    /*  Non-null *ret_dbg will cause problems dealing with
        DW_DLV_ERROR */
    *ret_dbg = 0;
    if (!path) {
        /* Oops. Null path */
        _dwarf_error_string(NULL,
            error,DW_DLE_STRING_PTR_NULL,
            "DW_DLE_STRING_PTR_NULL: Passing a"
            " null path argument to "
            "dwarf_init_path or dwarf_init_path_dl"
            " cannot work. Error.");
        return DW_DLV_ERROR;
    }
    /* a special dsym call so we only check once. */
    if (true_path_out_buffer) {
        res = dwarf_object_detector_path_dSYM(path,
            true_path_out_buffer,
            true_path_bufferlen,
            dl_path_array,dl_path_count,
            &ftype,&endian,&offsetsize,&filesize,
            &lpath_source,
            &errcode);
        if (res != DW_DLV_OK) {
            if (res == DW_DLV_ERROR) {
                /* ignore error. Look further. */
                errcode = 0;
            }
        }
    }
    if (res != DW_DLV_OK) {
        res = dwarf_object_detector_path_b(path,
            true_path_out_buffer,
            true_path_bufferlen,
            dl_path_array,dl_path_count,
            &ftype,&endian,&offsetsize,&filesize,
            &lpath_source,
            &errcode);
        if (res != DW_DLV_OK ) {
            if (res == DW_DLV_ERROR) {
                errcode = 0;
            }
        }
    }
    if (res != DW_DLV_OK) {
        /*  So as a last resort in case
            of data corruption in the object.
            Lets try without
            investigating debuglink  or dSYM. */
        res = dwarf_object_detector_path_b(path,
            0,
            0,
            dl_path_array,dl_path_count,
            &ftype,&endian,&offsetsize,&filesize,
            &lpath_source,
            &errcode);
    }
    if (res != DW_DLV_OK) {
        /* impossible. The last above *had* to work */
        if (res == DW_DLV_ERROR) {
            _dwarf_error(NULL, error, errcode);
        }
        return res;
    }
    /*  ASSERT: lpath_source != DW_PATHSOURCE_unspecified  */
    if (lpath_source != DW_PATHSOURCE_basic &&
        true_path_out_buffer && *true_path_out_buffer) {
        /* MacOS dSYM or GNU debuglink */
        file_path = true_path_out_buffer;
        fd = open_a_file(true_path_out_buffer);
    } else {
        /*  ASSERT: lpath_source = DW_PATHSOURCE_basic */
        file_path = (char *)path;
        fd = open_a_file(path);
    }

    if (fd == -1) {
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_UNAVAILABLE,
            DW_DLV_ERROR);
    }
    switch(ftype) {
    case DW_FTYPE_ELF: {
        res = _dwarf_elf_nlsetup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            close(fd);
            return res;
        }
        final_common_settings(dbg,file_path,fd,
            lpath_source,path_source,error);
        *ret_dbg = dbg;
        return res;
    }
    case DW_FTYPE_MACH_O: {
        res = _dwarf_macho_setup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            close(fd);
            return res;
        }
        final_common_settings(dbg,file_path,fd,
            lpath_source,path_source,error);
        *ret_dbg = dbg;
        return res;
    }
    case DW_FTYPE_PE: {
        res = _dwarf_pe_setup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            close(fd);
            return res;
        }
        final_common_settings(dbg,file_path,fd,
            lpath_source,path_source,error);
        *ret_dbg = dbg;
        return res;
    }
    default:
        close(fd);
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE,
            DW_DLV_ERROR);
    }
    return DW_DLV_NO_ENTRY;
}

/*  New March 2017, this provides for reading
    object files with multiple elf section groups.
    If you are unsure about group_number, use
    DW_GROUPNUMBER_ANY  as groupnumber.
*/
int
dwarf_init_b(int fd,
    unsigned        group_number,
    Dwarf_Handler   errhand,
    Dwarf_Ptr       errarg,
    Dwarf_Debug *   ret_dbg,
    Dwarf_Error *   error)
{
    unsigned ftype = 0;
    unsigned endian = 0;
    unsigned offsetsize = 0;
    Dwarf_Unsigned   filesize = 0;
    int res = 0;
    int errcode = 0;

    if (!ret_dbg) {
        DWARF_DBG_ERROR(NULL,DW_DLE_DWARF_INIT_DBG_NULL,DW_DLV_ERROR);
    }
    /*  Non-null *ret_dbg will cause problems dealing with
        DW_DLV_ERROR */
    *ret_dbg = 0;
    res = dwarf_object_detector_fd(fd, &ftype,
        &endian,&offsetsize,&filesize,&errcode);
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    if (res == DW_DLV_ERROR) {
        /* This macro does a return. */
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE, DW_DLV_ERROR);
    }
    switch(ftype) {
    case DW_FTYPE_ELF: {
        int res2 = 0;

        res2 = _dwarf_elf_nlsetup(fd,"",
            ftype,endian,offsetsize,filesize,
            group_number,errhand,errarg,ret_dbg,error);
        if (res2 != DW_DLV_OK) {
            return res2;
        }
        set_global_paths_init(*ret_dbg,error);
        return res2;
        }
    case DW_FTYPE_MACH_O: {
        int resm = 0;

        resm = _dwarf_macho_setup(fd,"",
            ftype,endian,offsetsize,filesize,
            group_number,errhand,errarg,ret_dbg,error);
        if (resm != DW_DLV_OK) {
            return resm;
        }
        set_global_paths_init(*ret_dbg,error);
        return resm;
        }

    case DW_FTYPE_PE: {
        int resp = 0;

        resp = _dwarf_pe_setup(fd,
            "",
            ftype,endian,offsetsize,filesize,
            group_number,errhand,errarg,ret_dbg,error);
        if (resp != DW_DLV_OK) {
            return resp;
        }
        set_global_paths_init(*ret_dbg,error);
        return resp;
        }
    default: break;
    }
    DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE, DW_DLV_ERROR);
    return res;
}

/*
    Frees all memory that was not previously freed
    by dwarf_dealloc.
    Aside from certain categories.

    Applicable when dwarf_init() or dwarf_elf_init()
    or the -b() form was used to init 'dbg'.
*/
int
dwarf_finish(Dwarf_Debug dbg)
{
    if (!dbg) {
        return DW_DLV_OK;
    }
    if (dbg->de_obj_file) {
        /*  The initial character of a valid
            dbg->de_obj_file->object struct is a letter:
            E, F, M, or P */
        char otype  = *(char *)(dbg->de_obj_file->ai_object);

        switch(otype) {
        case 'E':
            break;
        case 'F':
            /* Non-libelf elf access */
            _dwarf_destruct_elf_nlaccess(dbg->de_obj_file);
            break;
        case 'M':
            _dwarf_destruct_macho_access(dbg->de_obj_file);
            break;
        case 'P':
            _dwarf_destruct_pe_access(dbg->de_obj_file);
            break;
        default:
            /*  Do nothing. A serious internal error */
            break;
        }
    }
    if (dbg->de_owns_fd) {
        close(dbg->de_fd);
        dbg->de_owns_fd = FALSE;
    }
    free((void *)dbg->de_path);
    dbg->de_path = 0;
    /*  dwarf_object_finish() also frees de_path,
        but that is safe because we set it to zero
        here so no duplicate free will occur.
        It never returns DW_DLV_ERROR.
        Not all code uses libdwarf exactly as we do
        hence the free() there. */
    return dwarf_object_finish(dbg);
}

/*
    tieddbg should be the executable or .o
    that has the .debug_addr section that
    the base dbg refers to. See Split Objects in DWARF5.

    Allows setting to NULL (NULL is the default
    of  de_tied_data.td_tied_object).
    New September 2015.
*/
int
dwarf_set_tied_dbg(Dwarf_Debug dbg,
    Dwarf_Debug tieddbg,
    Dwarf_Error*error)
{
    if (!dbg) {
        DWARF_DBG_ERROR(NULL, DW_DLE_DBG_NULL, DW_DLV_ERROR);
    }
    dbg->de_tied_data.td_tied_object = tieddbg;
    if (tieddbg) {
        tieddbg->de_tied_data.td_is_tied_object = TRUE;
    }
    return DW_DLV_OK;
}

/*  New September 2015. */
int
dwarf_get_tied_dbg(Dwarf_Debug dbg, Dwarf_Debug *tieddbg_out,
    UNUSEDARG Dwarf_Error*error)
{
    *tieddbg_out = dbg->de_tied_data.td_tied_object;
    return DW_DLV_OK;
}
