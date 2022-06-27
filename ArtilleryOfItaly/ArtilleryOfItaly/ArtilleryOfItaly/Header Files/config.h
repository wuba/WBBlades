
/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Set to 1 as we are building with libelf */
/* #undef DWARF_WITH_LIBELF */

/* Define 1 if including a custom libelf library */
/* #undef HAVE_CUSTOM_LIBELF */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Set to 1 if the elf64_getehdr function is in libelf. */
/* #undef HAVE_ELF64_GETEHDR */

/* Set to 1 if the elf64_getshdr function is in libelf. */
/* #undef HAVE_ELF64_GETSHDR */

/* Define to 1 if you have the <elf.h> header file. */
/* #undef HAVE_ELF_H */

/* Define to 1 if you have the <libelf.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <libelf.h> header file. */
/* #undef HAVE_LIBELF_H */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <libelf/libelf.h> header file. */
/* #undef HAVE_LIBELF_LIBELF_H */

/* Define to 1 if you have the <malloc.h> header file. */
/* #undef HAVE_MALLOC_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Set to 1 if big endian . */
/* #undef WORDS_BIGENDIAN */

/* Define to 1 if you have the <sgidefs.h> header file. */
/* #undef HAVE_SGIDEFS_H */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to HAVE_UINTPTR_T 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1
/* Define to 1 if the system has the type `intptr_t'. */
#define HAVE_INTPTR_T


/*  Define to the uintptr_t to the type of an unsigned integer 
    type wide enough to hold a pointer
    if the system does not define it. */
/* #undef uintptr_t */
/* #undef intptr_t */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Set to 1 if __attribute__ ((unused)) is available. */
#define HAVE_UNUSED_ATTRIBUTE 1

/* Set to 1 if zlib decompression is available. */
#define HAVE_ZLIB 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
/* #undef LT_OBJDIR */

/* Name of package */
/* #undef PACKAGE */

/* Define to the address where bug reports for this package should be sent. */
/* #undef PACKAGE_BUGREPORT */

/* Define to the full name of this package. */
#define PACKAGE_NAME libdwarf

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libdwarf  0.4.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME

/* Define to the home page for this package. */
/* #undef PACKAGE_URL */


/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
/* #undef STDC_HEADERS */

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.4.0"

/* Version number of package */
#define VERSION   0.4.0 

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
/* #undef WORDS_BIGENDIAN */
# endif
#else
# ifndef WORDS_BIGENDIAN
#  undef WORDS_BIGENDIAN
# endif
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
#undef size_t

