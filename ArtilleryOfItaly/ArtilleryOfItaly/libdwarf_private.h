/*  Copyright 2022 David Anderson
    This trivial set of defines is hereby placed in the public domain
    for all to use without restriction.
*/
/* To enable printing with printf regardless of the
   actual underlying data type, we define the DW_PR_xxx macros.
   To ensure uses of DW_PR_DUx or DW_PR_DSx look the way you want
   ensure the DW_PR_XZEROS define as you want it.
*/
#ifndef LIBDWARF_PRIVATE_H
#define LIBDWARF_PRIVATE_H
#define DW_PR_XZEROS "08"

#ifdef _WIN32
#define DW_PR_DUx "I64x"
#define DW_PR_DSx "I64x"
#define DW_PR_DUu "I64u"
#define DW_PR_DSd "I64d"
#else
#define DW_PR_DUx "llx"
#define DW_PR_DSx "llx"
#define DW_PR_DUu "llu"
#define DW_PR_DSd "lld"
#endif /* DW_PR defines */

#ifdef HAVE_UNUSED_ATTRIBUTE
#define  UNUSEDARG __attribute__ ((unused))
#else
#define  UNUSEDARG
#endif

#ifndef TRUE
#define TRUE 1
#endif /* TRUE */
#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

#define DWARF_HALF_SIZE 2
#define SIZEOFT16 2
#define SIZEOFT32 4
#define SIZEOFT64 8

#ifdef WORDS_BIGENDIAN
#define ASNAR(func,t,s)                         \
    do {                                        \
        unsigned tbyte = sizeof(t) - sizeof(s); \
        (t) = 0;                                \
        (func)(((char *)&(t))+tbyte ,&(s)[0],sizeof(s));  \
    } while (0)
#else /* LITTLE ENDIAN */
#define ASNAR(func,t,s)                         \
    do {                                        \
        (t) = 0;                                \
        (func)(&(t),&(s)[0],sizeof(s));           \
    } while (0)
#endif /* end LITTLE- BIG-ENDIAN */

/* The following actually assumes (as used here)
    that t is 8 bytes (integer) while s is
    also 8 bytes (Dwarf_Sig8 struct).
    Just slightly different from the ASNAR generally
    used in libdwarf. Unusable in
    libdwarfp because of _dwarf_error() here.  */
#ifdef WORDS_BIGENDIAN
#define ASNARL(t,s,l)                     \
    do {                                  \
        unsigned tbyte = sizeof(t) - (l); \
        if (sizeof(t) < (l)) {            \
            _dwarf_error(dbg,error,DW_DLE_XU_HASH_INDEX_ERROR); \
            return DW_DLV_ERROR;          \
        }                                 \
        (t) = 0;                          \
        dbg->de_copy_word(((char *)&(t))+tbyte ,&(s)[0],(l));\
    } while (0)
#else /* LITTLE ENDIAN */
#define ASNARL(t,s,l)                 \
    do {                              \
        (t) = 0;                      \
        if (sizeof(t) < (l)) {        \
            _dwarf_error(dbg,error,DW_DLE_XU_HASH_INDEX_ERROR); \
            return DW_DLV_ERROR;      \
        }                             \
        dbg->de_copy_word(&(t),&(s)[0],(l));  \
    } while (0)
#endif /* end LITTLE- BIG-ENDIAN */

#ifdef WORDS_BIGENDIAN
#define SIGN_EXTEND(dest, length)                       \
    do {                                                \
        if (*(Dwarf_Sbyte *)((char *)&(dest) +          \
            sizeof(dest) - (length)) < 0) {             \
            memcpy((char *)&(dest),                     \
                "\xff\xff\xff\xff\xff\xff\xff\xff",     \
                sizeof(dest) - (length));               \
        }                                               \
    } while (0)
#else /* LITTLE ENDIAN */
#define SIGN_EXTEND(dest, length)                                 \
    do {                                                          \
        if (*(Dwarf_Sbyte *)((char *)&(dest)+ ((length)-1)) < 0) { \
            memcpy((char *)&(dest)+(length),                      \
                "\xff\xff\xff\xff\xff\xff\xff\xff",               \
                sizeof(dest) - (length));                         \
        }                                                         \
    } while (0)
#endif
#endif /* LIBDWARF_PRIVATE_H */
