#ifndef __LIBXLPY_SHEET__
#define __LIBXLPY_SHEET__

typedef struct {
	PyObject_HEAD
	SheetHandle handler;
} XLPySheet;

#endif
