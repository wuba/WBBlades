/*
Copyright (c) 2019-2021, David Anderson
All rights reserved.

Redistribution and use in source and binary forms, with
or without modification, are permitted provided that the
following conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the
    following disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the
    following disclaimer in the documentation and/or
    other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  */

#include <config.h>

#include <stdio.h>  /* printf() */
#include <stdlib.h> /* free() malloc() */
#include <string.h> /* memcpy() memset() strcmp() strdup() strlen() */

#if defined _WIN32
#ifdef HAVE_STDAFX_H
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */
#include <direct.h> /* getcwd */
#elif defined HAVE_UNISTD_H
#include <unistd.h> /* getcwd */
#endif /* _WIN32 */

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"
#include "dwarf_base_types.h"
#include "dwarf_global.h"
#include "dwarf_safe_strcpy.h"
#include "dwarf_opaque.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_string.h"
#include "dwarf_debuglink.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif /* O_BINARY */

#define MINBUFLEN 1000

#if _WIN32
#define NULL_DEVICE_NAME "NUL"
#else
#define NULL_DEVICE_NAME "/dev/null"
#endif /* _WIN32 */

static int
_dwarf_extract_buildid(Dwarf_Debug dbg,
    struct Dwarf_Section_s * pbuildid,
    unsigned        *type_returned,
    char           **owner_name_returned,
    unsigned char  **build_id_returned,
    unsigned        *build_id_length_returned,
    Dwarf_Error *error);

struct joins_s {
    dwarfstring js_dirname;
    dwarfstring js_basenamesimple;
    dwarfstring js_basesimpledebug;
    dwarfstring js_binname;
    dwarfstring js_cwd;
    dwarfstring js_originalfullpath;
    dwarfstring js_linkstring;
    dwarfstring js_tmp2;
    dwarfstring js_tmp3;
    dwarfstring js_buildid;
    dwarfstring js_buildid_filename;
};

static void
construct_js(struct joins_s * js)
{
    memset(js,0,sizeof(struct joins_s));
    dwarfstring_constructor(&js->js_dirname);
    dwarfstring_constructor(&js->js_basenamesimple);
    dwarfstring_constructor(&js->js_basesimpledebug);
    dwarfstring_constructor(&js->js_cwd);
    dwarfstring_constructor(&js->js_originalfullpath);
    dwarfstring_constructor(&js->js_linkstring);
    dwarfstring_constructor(&js->js_tmp2);
    dwarfstring_constructor(&js->js_tmp3);
    dwarfstring_constructor(&js->js_buildid);
    dwarfstring_constructor(&js->js_buildid_filename);
}
static void
destruct_js(struct joins_s * js)
{
    dwarfstring_destructor(&js->js_dirname);
    dwarfstring_destructor(&js->js_basenamesimple);
    dwarfstring_destructor(&js->js_basesimpledebug);
    dwarfstring_destructor(&js->js_cwd);
    dwarfstring_destructor(&js->js_originalfullpath);
    dwarfstring_destructor(&js->js_linkstring);
    dwarfstring_destructor(&js->js_tmp2);
    dwarfstring_destructor(&js->js_tmp3);
    dwarfstring_destructor(&js->js_buildid);
    dwarfstring_destructor(&js->js_buildid_filename);
}

static char joinchar = '/';
static char* joinstr = "/";
#if defined (_WIN32)
static char joincharw = '\\';
/*  Large enough it is unlikely dwarfstring will ever
    do a malloc here, Windows paths usually < 256 characters. */
static char winbuf[256];

static void
transformtoposix(dwarfstring * out, char *in)
{
    char *cp = in;

    for ( ; *cp  ; ++cp) {
        if ( *cp == joincharw ) {
            dwarfstring_append_length(out,joinstr,1);
        } else {
            dwarfstring_append_length(out,cp,1);
        }
    }
}

#endif /* _WIN32 */

/*  ASSERT: the target chars already have the transformtoposix()
    done.
*/
int
_dwarf_pathjoinl(dwarfstring *target,dwarfstring * input)
{
    char *inputs = dwarfstring_string(input);
    char *targ = dwarfstring_string(target);
    size_t targlen = 0;
#if defined (_WIN32)
    dwarfstring winput;

    dwarfstring_constructor_static(&winput,winbuf,sizeof(winbuf));
    transformtoposix(&winput,inputs);
    targlen = dwarfstring_strlen(target);
    inputs = dwarfstring_string(&winput);
    if (!targlen) {
        dwarfstring_append(target,inputs);
        return DW_DLV_OK;
    }
#else /* !_Windows */
    targlen = dwarfstring_strlen(target);
#endif /* _WIN32 */

    if (!targlen) {
        dwarfstring_append(target,inputs);
        return DW_DLV_OK;
    }
    targ = dwarfstring_string(target);
    if (targ[targlen-1] != joinchar) {
        if (*inputs != joinchar) {
            dwarfstring_append(target,joinstr);
            dwarfstring_append(target,inputs);
        } else {
            dwarfstring_append(target,inputs);
        }
    } else {
        if (*inputs != joinchar) {
            dwarfstring_append(target,inputs);
        } else {
            dwarfstring_append(target,inputs+1);
        }
    }
#if defined (_WIN32)
    dwarfstring_destructor(&winput);
#endif /* _WIN32 */
    return DW_DLV_OK;
}
/*  ASSERT: the last character in s is not a /  */
static size_t
mydirlen(char *s)
{
    char *cp = 0;
    char *lastjoinchar = 0;
    size_t count =0;

    for (cp = s ; *cp ; ++cp,++count)  {
        if (*cp == joinchar) {
            lastjoinchar = cp;
        }
    }
    if (lastjoinchar) {
        /*  ptrdiff_t is generated but not named */
        Dwarf_Unsigned sizetoendjoin =
            (lastjoinchar >= s)?(lastjoinchar-s):0xffffffff;
        /* count the last join as mydirlen. */
        if (sizetoendjoin == 0xffffffff) {
            /* impossible. */
            return 0;
        }
        return sizetoendjoin;
    }
    return 0;
}

struct dwarfstring_list_s {
    dwarfstring                dl_string;
    struct dwarfstring_list_s *dl_next;
};

static void
dwarfstring_list_constructor(struct dwarfstring_list_s *l)
{
    dwarfstring_constructor(&l->dl_string);
    l->dl_next = 0;
}

static int
dwarfstring_list_add_new(struct dwarfstring_list_s * base_entry,
    struct dwarfstring_list_s *prev,
    dwarfstring * input,
    struct dwarfstring_list_s ** new_out,
    int *errcode)
{
    struct dwarfstring_list_s *next = 0;
    if (prev) {
        next = ( struct dwarfstring_list_s *)
        malloc(sizeof(struct dwarfstring_list_s));
        if (!next) {
            *errcode = DW_DLE_ALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        dwarfstring_list_constructor(next);
    } else {
        next = base_entry;
    }
    dwarfstring_append(&next->dl_string,
        dwarfstring_string(input));
    if (prev) {
        prev->dl_next = next;
    }
    *new_out = next;
    return DW_DLV_OK;
}

/*  destructs passed in entry (does not free it) and all
    those on the dl_next list (those are freed). */
static void
dwarfstring_list_destructor(struct dwarfstring_list_s *l)
{
    struct dwarfstring_list_s *curl = l;
    struct dwarfstring_list_s *nextl = l;

    nextl = curl->dl_next;
    dwarfstring_destructor(&curl->dl_string);
    curl->dl_next = 0;
    curl = nextl;
    for ( ; curl ; curl = nextl) {
        nextl = curl->dl_next;
        dwarfstring_destructor(&curl->dl_string);
        curl->dl_next = 0;
        free(curl);
    }
}

static void
prepare_linked_name(dwarfstring *out,
    dwarfstring *dirname,
    dwarfstring *extradir,
    dwarfstring *linkname)
{
    dwarfstring_append(out, dwarfstring_string(dirname));
    if (extradir) {
        _dwarf_pathjoinl(out,extradir);
    }
    _dwarf_pathjoinl(out,linkname);
}

static void
build_buildid_filename(dwarfstring *target,
    unsigned buildid_length,
    unsigned char *buildid)
{
    dwarfstring tmp;
    unsigned bu = 0;
    unsigned char *cp  = 0;

    dwarfstring_constructor(&tmp);
    dwarfstring_append(&tmp,".build-id");
    dwarfstring_append(&tmp,joinstr);
    cp = buildid;
    for (bu = 0; bu < buildid_length; ++bu ,++cp) {
        dwarfstring_append_printf_u(&tmp, "%02x",*cp);
        if (bu == 0) {
            dwarfstring_append(&tmp,"/");
        }
    }
    _dwarf_pathjoinl(target,&tmp);
    dwarfstring_append(target,".debug");
    dwarfstring_destructor(&tmp);
    return;
}

#if 0
static void
dump_bytes(const char *msg,unsigned char * start, unsigned len)
{
    Dwarf_Small *end = start + len;
    Dwarf_Small *cur = start;
    printf("%s (0x%lx) ",msg,(unsigned long)start);
    for (; cur < end; cur++) {
        printf("%02x", *cur);
    }
    printf("\n");
}
#endif /*0*/

/*  If the compiler or the builder of the object file
    being read has made a mistake it is possible
    for a constructed name to match the original
    file path, yet we do not want to add that to
    the search path. */
static int
duplicatedpath(dwarfstring* l,
    dwarfstring*r)
{
    if (strcmp(dwarfstring_string(l),
        dwarfstring_string(r))) {
        return FALSE;
    }
    /*  Oops. somebody made a mistake */
    return TRUE;
}

/*  New September 2019.  Access to the GNU section named
    .gnu_debuglink
    See
    https://sourceware.org/gdb/onlinedocs/
        gdb/Separate-Debug-Files.html
    The default global path was set
    to /usr/lib/debug
    by set_global_paths_init()
    called at libdwarf object init time.
    So there is always the default
    global path present.
*/
int
_dwarf_construct_linkedto_path(
    char         **global_prefixes_in,
    unsigned       length_global_prefixes_in,
    char          *pathname_in,
    char          *link_string_in, /* from debug link */
    dwarfstring   *link_string_fullpath_out,
    UNUSEDARG unsigned char *crc_in, /* from debug_link, 4 bytes */
    unsigned char *buildid, /* from gnu buildid */
    unsigned       buildid_length, /* from gnu buildid */
    char        ***paths_out,
    unsigned      *paths_out_length,
    int *errcode)
{
    char * depath = pathname_in;
    int res = 0;
    struct joins_s joind;
    size_t dirnamelen = 0;
    struct dwarfstring_list_s base_dwlist;
    struct dwarfstring_list_s *last_entry = 0;
    unsigned global_prefix_number = 0;

    dwarfstring_list_constructor(&base_dwlist);
    construct_js(&joind);
    dirnamelen = mydirlen(depath);
    if (dirnamelen) {
        /*  Original dirname, before cwd (if needed) */
        dwarfstring_append_length(&joind.js_tmp2,
            depath,dirnamelen);
    }
    if (depath[0] != joinchar) {
        /*  Meaning a/b or b, not /a/b or /b ,
            so we apply cwd */
        char  buffer[2000];
        unsigned buflen= sizeof(buffer);
        char *wdret = 0;

        buffer[0] = 0;
        wdret = getcwd(buffer,buflen);
        if (!wdret) {
            printf("getcwd() issue. Do nothing. "
                " line  %d %s\n",__LINE__,__FILE__);
            dwarfstring_list_destructor(&base_dwlist);
            destruct_js(&joind);
            *errcode = DW_DLE_ALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        dwarfstring_append(&joind.js_cwd,buffer);
        dwarfstring_append(&joind.js_dirname,buffer);
        _dwarf_pathjoinl(&joind.js_dirname,&joind.js_tmp2);
        buffer[0] = 0;
    }  else {/* else leave js_cwd empty */
        dwarfstring_append(&joind.js_dirname,
            dwarfstring_string(&joind.js_tmp2));
    }

    /* Creating a real basename. No slashes. */
    dwarfstring_append(&joind.js_basenamesimple,
        depath+dirnamelen);
    dwarfstring_append(&joind.js_basesimpledebug,
        dwarfstring_string(&joind.js_basenamesimple));
    dwarfstring_append(&joind.js_basesimpledebug,".debug");

    build_buildid_filename(&joind.js_buildid_filename,
        buildid_length, buildid);
    dwarfstring_reset(&joind.js_tmp2);

    /*  Now js_dirname / js_basenamesimple
        are reflecting a full path  */

    /*  saves the full path to the original
        executable */
    dwarfstring_append(&joind.js_originalfullpath,
        dwarfstring_string(&joind.js_dirname));
    _dwarf_pathjoinl(&joind.js_originalfullpath,
        &joind.js_basenamesimple);

    /*  js_originalfullpath is a true full path
        to the object we started with as input. */
    /*  First, do the build-id method if it applies
        at all */
    for (global_prefix_number = 0;
        buildid_length &&
        (global_prefix_number < length_global_prefixes_in);
        ++global_prefix_number) {
        char * prefix = 0;
        struct dwarfstring_list_s *now_last = 0;

        prefix = global_prefixes_in[global_prefix_number];
        dwarfstring_reset(&joind.js_buildid);
        dwarfstring_append(&joind.js_buildid,prefix);
        _dwarf_pathjoinl(&joind.js_buildid,
            &joind.js_buildid_filename);
        res = dwarfstring_list_add_new(
            &base_dwlist,
            last_entry,&joind.js_buildid,
            &now_last,errcode);
        if (res != DW_DLV_OK) {
            dwarfstring_list_destructor(&base_dwlist);
            destruct_js(&joind);
            return res;
        }
            last_entry = now_last;
    } /* end loop on global prefix numbers */
    /* end of the build-id name-finding. */

    /*  Now for the debug link method of finding debug
        files. */
    if (link_string_in) {
        /* First try dir of executable */
        struct dwarfstring_list_s *now_last = 0;

        dwarfstring_append(&joind.js_linkstring,
            link_string_in);
        dwarfstring_reset(&joind.js_tmp3);
        dwarfstring_reset(&joind.js_tmp2);
        prepare_linked_name(&joind.js_tmp3,
            &joind.js_dirname,
            0,&joind.js_linkstring);
        dwarfstring_append(link_string_fullpath_out,
            dwarfstring_string(&joind.js_tmp3));
        if (!duplicatedpath(&joind.js_originalfullpath,
            &joind.js_tmp3)) {
            res = dwarfstring_list_add_new(
                &base_dwlist,
                last_entry,&joind.js_tmp3,
                &now_last,errcode);
            if (res != DW_DLV_OK) {
                dwarfstring_list_destructor(&base_dwlist);
                destruct_js(&joind);
                return res;
            }
            last_entry = now_last;
        }
        dwarfstring_reset(&joind.js_tmp2);
        dwarfstring_reset(&joind.js_tmp3);
        dwarfstring_append(&joind.js_tmp3,".debug");
        prepare_linked_name(&joind.js_tmp2,
            &joind.js_dirname,
            &joind.js_tmp3,&joind.js_linkstring);
        if (! duplicatedpath(&joind.js_originalfullpath,
            &joind.js_tmp2)) {
            res = dwarfstring_list_add_new(
                &base_dwlist,
                last_entry,&joind.js_tmp2,
                &now_last,errcode);
            if (res != DW_DLV_OK) {
                dwarfstring_list_destructor(&base_dwlist);
                destruct_js(&joind);
                return res;
            }
            last_entry = now_last;
        }
        /*  Now look in the global locations. */
        for (global_prefix_number = 0;
            global_prefix_number < length_global_prefixes_in;
            ++global_prefix_number) {
            char * prefix =
                global_prefixes_in[global_prefix_number];

            dwarfstring_reset(&joind.js_tmp2);
            dwarfstring_reset(&joind.js_tmp3);
            dwarfstring_append(&joind.js_tmp2, prefix);
            prepare_linked_name(&joind.js_tmp3,
                &joind.js_tmp2,
                &joind.js_dirname,
                &joind.js_linkstring);
            if (!duplicatedpath(&joind.js_originalfullpath,
                &joind.js_tmp3)) {
                res = dwarfstring_list_add_new(
                    &base_dwlist,
                    last_entry,&joind.js_tmp3,
                    &now_last,errcode);
                if (res != DW_DLV_OK) {
                    dwarfstring_list_destructor(&base_dwlist);
                        destruct_js(&joind);
                    return res;
                }
                last_entry = now_last;
            }
        }
    }

    /*  Now malloc space for the pointer array
        and the strings they point at so a simple
        free by our caller will clean up
        everything.  Copy the data from
        base_dwlist to the new area. */
    {
        struct dwarfstring_list_s *cur = 0;
        char **resultfullstring = 0;

        unsigned long count = 0;
        unsigned long pointerarraysize = 0;
        unsigned long sumstringlengths = 0;
        unsigned long totalareasize = 0;
        unsigned long setptrindex = 0;
        unsigned long setstrindex = 0;

        cur = &base_dwlist;
        for ( ; cur ; cur = cur->dl_next) {
            ++count;
            pointerarraysize += sizeof(void *);
            sumstringlengths +=
                dwarfstring_strlen(&cur->dl_string) +1;
        }
        /*  Make a final null pointer in the pointer array. */
        pointerarraysize += sizeof(void *);
        totalareasize = pointerarraysize + sumstringlengths +8;
        resultfullstring = (char **)malloc(totalareasize);
        setstrindex = pointerarraysize;
        if (!resultfullstring) {
            dwarfstring_list_destructor(&base_dwlist);
            destruct_js(&joind);
            *errcode = DW_DLE_ALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        memset(resultfullstring,0,totalareasize);
        cur = &base_dwlist;

        for ( ; cur ; cur = cur->dl_next,++setptrindex) {
            char **iptr = (char **)((char *)resultfullstring +
                setptrindex*sizeof(void *));
            char *sptr = (char*)resultfullstring + setstrindex;
            char *msg = dwarfstring_string(&cur->dl_string);
            unsigned long slen = dwarfstring_strlen(&cur->dl_string);

            _dwarf_safe_strcpy(sptr,totalareasize - setstrindex,
                msg,slen);
            setstrindex += slen +1;
            *iptr = sptr;
        }
        *paths_out = resultfullstring;
        *paths_out_length = count;
    }
    dwarfstring_list_destructor(&base_dwlist);
    destruct_js(&joind);
    return DW_DLV_OK;
}
static int
_dwarf_extract_debuglink(Dwarf_Debug dbg,
    struct Dwarf_Section_s * pdebuglink,
    char ** name_returned,  /* static storage, do not free */
    unsigned char ** crc_returned,   /* 32bit crc , do not free */
    Dwarf_Error *error)
{
    Dwarf_Small *ptr = 0;
    Dwarf_Small *endptr = 0;
    unsigned namelen = 0;
    unsigned m = 0;
    unsigned incr = 0;
    Dwarf_Small *crcptr = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Unsigned secsize = 0;

    if (!pdebuglink->dss_data) {
        return DW_DLV_NO_ENTRY;
    }
    secsize = pdebuglink->dss_size;
    ptr = pdebuglink->dss_data;
    endptr = ptr + secsize;

    res = _dwarf_check_string_valid(dbg,ptr,
        ptr, endptr,  DW_DLE_FORM_STRING_BAD_STRING,
        error);
    if ( res != DW_DLV_OK) {
        return res;
    }
    namelen = (unsigned)strlen((const char*)ptr);
    m = (namelen+1) %4;
    if (m) {
        incr = 4 - m;
    }
    crcptr = (unsigned char *)ptr +namelen +1 +incr;
    if ((crcptr +4) != (unsigned char*)endptr) {
        _dwarf_error(dbg,error,DW_DLE_CORRUPT_GNU_DEBUGLINK);
        return DW_DLV_ERROR;
    }
    *name_returned = (char *)ptr;
    *crc_returned = crcptr;
    return DW_DLV_OK;
}

/*  The definition of .note.gnu.buildid contents (also
    used for other GNU .note.gnu.  sections too. */
struct buildid_s {
    char bu_ownernamesize[4];
    char bu_buildidsize[4];
    char bu_type[4];
    char bu_owner[1];
};

static int
_dwarf_extract_buildid(Dwarf_Debug dbg,
    struct Dwarf_Section_s * pbuildid,
    unsigned       * type_returned,
    char           **owner_name_returned,
    unsigned char  **build_id_returned,
    unsigned       * build_id_length_returned,
    Dwarf_Error     *error)
{
    Dwarf_Small * ptr = 0;
    Dwarf_Small * endptr = 0;
    int res = DW_DLV_ERROR;
    struct buildid_s *bu = 0;
    Dwarf_Unsigned namesize = 0;
    Dwarf_Unsigned descrsize = 0;
    Dwarf_Unsigned type = 0;
    Dwarf_Unsigned finalsize;
    Dwarf_Unsigned secsize = 0;

    if (!pbuildid->dss_data) {
        return DW_DLV_NO_ENTRY;
    }
    secsize = pbuildid->dss_size;
    ptr = pbuildid->dss_data;
    if (secsize < sizeof(struct buildid_s)) {
        _dwarf_error(dbg,error,DW_DLE_CORRUPT_NOTE_GNU_DEBUGID);
        return DW_DLV_ERROR;
    }
    endptr = ptr + secsize;
    /*  We hold gh_content till all is closed
        as we return pointers into it
        if all goes well. */
    bu = (struct buildid_s *)ptr;
    ASNAR(dbg->de_copy_word,namesize, bu->bu_ownernamesize);
    ASNAR(dbg->de_copy_word,descrsize,bu->bu_buildidsize);
    ASNAR(dbg->de_copy_word,type,     bu->bu_type);
    if (descrsize != 20) {
        _dwarf_error(dbg,error,DW_DLE_CORRUPT_NOTE_GNU_DEBUGID);
        return DW_DLV_ERROR;
    }
    res = _dwarf_check_string_valid(dbg,
        (Dwarf_Small *)&bu->bu_owner[0],
        (Dwarf_Small *)&bu->bu_owner[0],
        endptr,
        DW_DLE_CORRUPT_GNU_DEBUGID_STRING,
        error);
    if ( res != DW_DLV_OK) {
        return res;
    }
    if ((strlen(bu->bu_owner) +1) != namesize) {
        _dwarf_error(dbg,error, DW_DLE_CORRUPT_GNU_DEBUGID_STRING);
        return DW_DLV_ERROR;
    }

    finalsize = sizeof(struct buildid_s)-1 + namesize + descrsize;
    if (finalsize > secsize) {
        _dwarf_error(dbg,error, DW_DLE_CORRUPT_GNU_DEBUGID_SIZE);
        return DW_DLV_ERROR;
    }
    *type_returned = type;
    *owner_name_returned = &bu->bu_owner[0];
    *build_id_length_returned = descrsize;
    *build_id_returned = (unsigned char *)ptr +
        sizeof(struct buildid_s)-1 + namesize;
    return DW_DLV_OK;
}

/*  Caller frees space returned  by debuglink_fillpath_returned and
    The following return pointers into the dbg itself
    and are only valid while that dbg is open.
    debuglink_path_returned.
    crc_returned, buildid_owner_name_returned,
    buildid_returned, */
int
dwarf_gnu_debuglink(Dwarf_Debug dbg,
    char     **  debuglink_path_returned, /* do not free*/
    unsigned char **  crc_returned,
    char     **  debuglink_fullpath_returned, /* caller frees */
    unsigned *   debuglink_fullpath_length_returned,

    unsigned *   buildid_type_returned ,
    char     **  buildid_owner_name_returned,
    unsigned char ** buildid_returned,
    unsigned *   buildid_length_returned,
    char     *** paths_returned,
    unsigned   * paths_count_returned,
    Dwarf_Error* error)
{
    dwarfstring debuglink_fullpath;
    int res = DW_DLV_ERROR;
    char * pathname = 0;
    int errcode = 0;
    struct Dwarf_Section_s * pdebuglink = 0;
    struct Dwarf_Section_s * pbuildid = 0;

    if (dbg->de_gnu_debuglink.dss_size) {
        pdebuglink = &dbg->de_gnu_debuglink;
        res = _dwarf_load_section(dbg, pdebuglink,error);
        if (res == DW_DLV_ERROR) {
            return res;
        }
    }
    if (dbg->de_note_gnu_buildid.dss_size) {
        pbuildid = &dbg->de_note_gnu_buildid;
        res = _dwarf_load_section(dbg, pbuildid,error);
        if (res == DW_DLV_ERROR) {
            return res;
        }
    }
    if (!pdebuglink && !pbuildid) {
        return DW_DLV_NO_ENTRY;
    }
    if (pdebuglink) {
        int linkres = 0;

        linkres = _dwarf_extract_debuglink(dbg,
            pdebuglink,
            debuglink_path_returned,
            crc_returned,
            error);
        if (linkres == DW_DLV_ERROR) {
            return linkres;
        }
    }
    if (pbuildid) {
        int buildidres = 0;
        buildidres = _dwarf_extract_buildid(dbg,
            pbuildid,
            buildid_type_returned,
            buildid_owner_name_returned,
            buildid_returned,
            buildid_length_returned,
            error);
        if (buildidres == DW_DLV_ERROR) {
            return buildidres;
        }
    }

    dwarfstring_constructor(&debuglink_fullpath);
    pathname = (char *)dbg->de_path;
    if (pathname && paths_returned) {
        res =  _dwarf_construct_linkedto_path(
            (char **)dbg->de_gnu_global_paths,
            dbg->de_gnu_global_path_count,
            pathname,
            *debuglink_path_returned,
            &debuglink_fullpath,
            *crc_returned,
            *buildid_returned,
            *buildid_length_returned,
            paths_returned,
            paths_count_returned,
            &errcode);
        if (res != DW_DLV_OK) {
            dwarfstring_destructor(&debuglink_fullpath);
            return res;
        }
        if (dwarfstring_strlen(&debuglink_fullpath)) {
            *debuglink_fullpath_returned =
                strdup(dwarfstring_string(&debuglink_fullpath));
            *debuglink_fullpath_length_returned =
                dwarfstring_strlen(&debuglink_fullpath);
        }
    } else if (paths_count_returned) {
        *paths_count_returned = 0;
    } else {
        /* nothing special to do */
    }
    dwarfstring_destructor(&debuglink_fullpath);
    return DW_DLV_OK;
}

/*  This should be rarely called and most likely
    only once (at dbg init time from dwarf_generic_init.c,
    see set_global_paths_init()).
    Maybe once or twice later.
*/
int
dwarf_add_debuglink_global_path(Dwarf_Debug dbg,
    const char *pathname,
    Dwarf_Error *error)
{
    unsigned    glpath_count_in = 0;
    unsigned    glpath_count_out = 0;
    const char **glpaths = 0;
    const char * path1 = 0;

    glpath_count_in = dbg->de_gnu_global_path_count;
    glpath_count_out = glpath_count_in+1;
    glpaths = (const char **)malloc(sizeof(char *)*
        glpath_count_out);
    if (!glpaths) {
        _dwarf_error(dbg,error,DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    if (glpath_count_in) {
        memcpy(glpaths, dbg->de_gnu_global_paths,
            sizeof(char *)*glpath_count_in);
    }
    path1 = strdup(pathname);
    if (!path1) {
        free(glpaths);
        _dwarf_error(dbg,error,DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    free((char *)dbg->de_gnu_global_paths);
    glpaths[glpath_count_in] = path1;
    dbg->de_gnu_global_paths = (const char **)glpaths;
    dbg->de_gnu_global_path_count = glpath_count_out;
    return DW_DLV_OK;
}
