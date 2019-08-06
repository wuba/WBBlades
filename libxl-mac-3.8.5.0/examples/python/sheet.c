#include <Python.h>
#include <libxl.h>

#include "sheet.h"
#include "format.h"

extern PyTypeObject XLPyFormatType;

enum MarginSide { LEFT, RIGHT, TOP, BOTTOM };

static int
init(XLPySheet *self)
{
    return 0;
}

static void
dealloc(XLPySheet *self)
{
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
cell_type(XLPySheet *self, PyObject *args)
{
    int row, col;
    if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;
    return Py_BuildValue("i",
            xlSheetCellType(self->handler, row, col));
}

static PyObject *
is_formula(XLPySheet *self, PyObject *args)
{
    int row, col;
    if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;
    if (xlSheetIsFormula(self->handler, row, col))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
cell_format(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = xlSheetCellFormat(self->handler, row, col);
	if(!fmt) Py_RETURN_NONE;

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return (PyObject *)obj;
}

static PyObject *
set_cell_format(XLPySheet *self, PyObject *args)
{
	const int row, col;
	XLPyFormat *fmt;
	if(!PyArg_ParseTuple(args, "iiO!", &row, &col, &XLPyFormatType, &fmt))
		return NULL;

	xlSheetSetCellFormat(self->handler, row, col, fmt->handler);
	Py_RETURN_NONE;
}

static PyObject *
read_str(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = NULL;
	const char *str = xlSheetReadStr(self->handler, row, col, &fmt);
	if(!str) Py_RETURN_NONE;

	if(!fmt) return Py_BuildValue("(sO)", str, Py_None);

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return Py_BuildValue("(sO)", str, obj);
}

static PyObject *
write_str(XLPySheet *self, PyObject *args)
{
	const int row, col;
	const char *val;
	XLPyFormat *fmt = NULL;
	if(!PyArg_ParseTuple(args, "iis|O!", &row, &col, &val, &XLPyFormatType,
				&fmt)) return NULL;

	if (!xlSheetWriteStr(self->handler, row, col, val,
				fmt ? fmt->handler : NULL)) Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
read_num(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = NULL;
	double num;
	num = xlSheetReadNum(self->handler, row, col, &fmt);

	if(!fmt) return Py_BuildValue("(dO)", num, Py_None);

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return Py_BuildValue("(dO)", num, obj);
}

static PyObject *
write_num(XLPySheet *self, PyObject *args)
{
	int row, col;
	double val;
	XLPyFormat *fmt = NULL;
	if(!PyArg_ParseTuple(args, "iid|O!", &row, &col, &val, &XLPyFormatType,
				&fmt)) return NULL;

	if (!xlSheetWriteNum(self->handler, row, col, val,
				fmt ? fmt->handler : NULL)) Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
read_bool(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = NULL;
	int val = xlSheetReadBool(self->handler, row, col, &fmt);

	if(!fmt) return Py_BuildValue("(OO)",
			(0 == val) ? Py_False : Py_True, Py_None);

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return Py_BuildValue("(OO)",
			(0 == val) ? Py_False : Py_True, obj);
}

static PyObject *
write_bool(XLPySheet *self, PyObject *args)
{
	int row, col;
	PyObject *val;
	XLPyFormat *fmt = NULL;
	if(!PyArg_ParseTuple(args, "iiO!|O!", &row, &col, &PyBool_Type, &val,
				&XLPyFormatType, &fmt)) return NULL;

	if (!xlSheetWriteBool(self->handler, row, col, PyObject_IsTrue(val),
				fmt ? fmt->handler : NULL)) Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
read_blank(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = NULL;
	int val = xlSheetReadBlank(self->handler, row, col, &fmt);

	if(!fmt) return Py_BuildValue("(OO)",
			(0 == val) ? Py_False : Py_True, Py_None);

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return Py_BuildValue("(OO)",
			(0 == val) ? Py_False : Py_True, obj);
}

static PyObject *
write_blank(XLPySheet *self, PyObject *args)
{
	int row, col;
	XLPyFormat *fmt = NULL;
	if(!PyArg_ParseTuple(args, "ii|O!", &row, &col, &XLPyFormatType, &fmt))
		return NULL;

	if (!xlSheetWriteBlank(self->handler, row, col,
				fmt ? fmt->handler : NULL)) Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
read_formula(XLPySheet *self, PyObject *args)
{
	const int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	FormatHandle fmt = NULL;
	const char *val = xlSheetReadFormula(self->handler, row, col, &fmt);

	if(!fmt) return Py_BuildValue("(sO)", val, Py_None);

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = fmt;
	return Py_BuildValue("(sO)", val, obj);
}

static PyObject *
write_formula(XLPySheet *self, PyObject *args)
{
	int row, col;
	const char *val;
	XLPyFormat *fmt = NULL;
	if(!PyArg_ParseTuple(args, "iis|O!", &row, &col, &val, &XLPyFormatType,
				&fmt)) return NULL;

	if (!xlSheetWriteFormula(self->handler, row, col, val,
				fmt ? fmt->handler : NULL)) Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
read_comment(XLPySheet *self, PyObject *args)
{
	int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	const char *str = xlSheetReadComment(self->handler, row, col);
	return Py_BuildValue("s", str);
}

static PyObject *
write_comment(XLPySheet *self, PyObject *args)
{
	int row, col;
	const char *value, *author = NULL;
	int width = 0, height = 0;
	if(!PyArg_ParseTuple(args, "iis|sii", &row, &col, &value, &author,
				&width, &height)) return NULL;

	xlSheetWriteComment(self->handler, row, col, value, author, width, height);
	Py_RETURN_NONE;
}

static PyObject *
is_date(XLPySheet *self, PyObject *args)
{
	int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	if(xlSheetIsDate(self->handler, row, col))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
read_error(XLPySheet *self, PyObject *args)
{
	int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	return Py_BuildValue("i",
			xlSheetReadError(self->handler, row, col));
}

static PyObject *
col_width(XLPySheet *self, PyObject *args)
{
	int col;
	if(!PyArg_ParseTuple(args, "i", &col)) return NULL;
	return Py_BuildValue("d", xlSheetColWidth(self->handler, col));
}

static PyObject *
row_height(XLPySheet *self, PyObject *args)
{
	int row;
	if(!PyArg_ParseTuple(args, "i", &row)) return NULL;
	return Py_BuildValue("d", xlSheetRowHeight(self->handler, row));
}

static PyObject *
set_col(XLPySheet *self, PyObject *args, PyObject *kwargs)
{
	int colFirst, colLast;
	double width;
	XLPyFormat *fmt = NULL;
	PyObject *hidden = NULL;
	static char *kwlist [] = {
		"colFirst",
		"colLast",
		"width",
		"format",
		"hidden",
		NULL
	};
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "iid|O!O!", kwlist,
				&colFirst, &colLast, &width,
				&XLPyFormatType, &fmt,
				&PyBool_Type, &hidden)) {
		return NULL;
	}

	if(!hidden) hidden = Py_False;
	if(xlSheetSetCol(self->handler, colFirst, colLast, width,
				(NULL != fmt) ? fmt->handler : 0,
				PyObject_IsTrue(hidden))) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *
set_row(XLPySheet *self, PyObject *args, PyObject *kwargs)
{
	int row;
	double height;
	XLPyFormat *fmt = NULL;
	PyObject *hidden = NULL;
	static char *kwlist [] = {
		"row",
		"height",
		"format",
		"hidden",
		NULL
	};
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "id|O!O!", kwlist,
				&row, &height,
				&XLPyFormatType, &fmt,
				&PyBool_Type, &hidden)) {
		return NULL;
	}

	if(!hidden) hidden = Py_False;
	if(xlSheetSetRow(self->handler, row, height,
				(NULL != fmt) ? fmt->handler : 0, PyObject_IsTrue(hidden)))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
row_hidden(XLPySheet *self, PyObject *args)
{
	int row;
	if(!PyArg_ParseTuple(args, "i", &row)) return NULL;
	if(xlSheetRowHidden(self->handler, row))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_row_hidden(XLPySheet *self, PyObject *args)
{
	int row;
	PyObject *hidden = NULL;

	if(!PyArg_ParseTuple(args, "iO!", &row, &PyBool_Type, &hidden)) return NULL;
	if(xlSheetSetRowHidden(self->handler, row, PyObject_IsTrue(hidden)))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
col_hidden(XLPySheet *self, PyObject *args)
{
	int col;
	if(!PyArg_ParseTuple(args, "i", &col)) return NULL;
	if(xlSheetColHidden(self->handler, col))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_col_hidden(XLPySheet *self, PyObject *args)
{
	int col;
	PyObject *hidden = NULL;

	if(!PyArg_ParseTuple(args, "iO!", &col, &PyBool_Type, &hidden)) return NULL;
	if(xlSheetSetColHidden(self->handler, col, PyObject_IsTrue(hidden)))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
get_merge(XLPySheet *self, PyObject *args)
{
	int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	int rowFirst, rowLast, colFirst, colLast;
	if(!xlSheetGetMerge(self->handler, row, col, &rowFirst, &rowLast, &colFirst,
		&colLast)) {
		Py_RETURN_NONE;
	}

	return Py_BuildValue("(iiii)", rowFirst, rowLast, colFirst, colLast);
}

static PyObject *
set_merge(XLPySheet *self, PyObject *args)
{
	int rowFirst, rowLast, colFirst, colLast;
	if(!PyArg_ParseTuple(args, "iiii", &rowFirst, &rowLast, &colFirst, &colLast)) {
		return NULL;
	}

	if(xlSheetSetMerge(self->handler, rowFirst, rowLast, colFirst, colLast)) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *
del_merge(XLPySheet *self, PyObject *args)
{
	int row, col;
	if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

	if(!xlSheetDelMerge(self->handler, row, col))
		Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
picture_size(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetPictureSize(self->handler));
}

static PyObject *
get_picture(XLPySheet *self, PyObject *args)
{
	int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;

	int rowTop, colLeft, rowBottom, colRight, width, height, offset_x, offset_y;

	if(-1 == xlSheetGetPicture(self->handler, index, &rowTop, &colLeft,
		&rowBottom, &colRight, &width, &height, &offset_x, &offset_y)) {
		Py_RETURN_NONE;
	}

	return Py_BuildValue("((ii)iiiiii)",
		rowTop, colLeft, rowBottom, colRight, width, height, offset_x, offset_y);
}

static PyObject *
set_picture(XLPySheet *self, PyObject *args)
{
    int row, col, pictureId;
    double scale;
    int offset_x, offset_y;
    if(!PyArg_ParseTuple(args, "iiidii",
                &row, &col, &pictureId, &scale, &offset_x, &offset_y)) {
        return NULL;
    }

    xlSheetSetPicture(self->handler, row, col,
            pictureId, scale, offset_x, offset_y, 0);
    Py_RETURN_NONE;
}

static PyObject *
set_picture_2(XLPySheet *self, PyObject *args)
{
    int row, col, pictureId;
    int width, height;
    int offset_x, offset_y;
    if(!PyArg_ParseTuple(args, "iiiiiii", &row, &col, &pictureId,
                &width, &height, &offset_x, &offset_y)) {
        return NULL;
    }

    xlSheetSetPicture2(self->handler, row, col,
            pictureId, width, height, offset_x, offset_y, 0);
    Py_RETURN_NONE;
}

static PyObject *
get_hor_page_break(XLPySheet *self, PyObject *args)
{
	int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;
	return Py_BuildValue("i", xlSheetGetHorPageBreak(self->handler, index));
}

static PyObject *
get_hor_page_break_size(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetGetHorPageBreakSize(self->handler));
}

static PyObject *
get_ver_page_break(XLPySheet *self, PyObject *args)
{
	int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;
	return Py_BuildValue("i", xlSheetGetVerPageBreak(self->handler, index));
}

static PyObject *
get_ver_page_break_size(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetGetVerPageBreakSize(self->handler));
}

static PyObject *
set_hor_page_break(XLPySheet *self, PyObject *args)
{
	int row, pageBreak;
	if(!PyArg_ParseTuple(args, "ii", &row, &pageBreak)) return NULL;

	if(!xlSheetSetHorPageBreak(self->handler, row, pageBreak))
		Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
set_ver_page_break(XLPySheet *self, PyObject *args)
{
	int col, pageBreak;
	if(!PyArg_ParseTuple(args, "ii", &col, &pageBreak)) return NULL;

	if(!xlSheetSetVerPageBreak(self->handler, col, pageBreak))
		Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
split(XLPySheet *self, PyObject *args)
{
    int row, col;
    if(!PyArg_ParseTuple(args, "ii", &row, &col)) return NULL;

    xlSheetSplit(self->handler, row, col);
    Py_RETURN_NONE;
}

static PyObject *
group_rows(XLPySheet *self, PyObject *args)
{
    int rowFirst, rowLast;
    PyObject *collapsed;
    if(!PyArg_ParseTuple(args, "iiO!", &rowFirst, &rowLast, &PyBool_Type, &collapsed)) return NULL;

    if(xlSheetGroupRows(self->handler, rowFirst, rowLast,
    			PyObject_IsTrue(collapsed))) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
group_cols(XLPySheet *self, PyObject *args)
{
    int colFirst, colLast;
    PyObject *collapsed;
    if(!PyArg_ParseTuple(args, "iiO!", &colFirst, &colLast, &PyBool_Type, &collapsed)) return NULL;

    if(xlSheetGroupCols(self->handler, colFirst, colLast,
    			PyObject_IsTrue(collapsed))) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
group_summary_below(XLPySheet *self)
{
	if(xlSheetGroupSummaryBelow(self->handler)) Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_group_summary_below(XLPySheet *self, PyObject *args)
{
	PyObject *below;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &below)) return NULL;

	xlSheetSetGroupSummaryBelow(self->handler, PyObject_IsTrue(below));
	Py_RETURN_NONE;
}

static PyObject *
group_summary_right(XLPySheet *self)
{
	if(xlSheetGroupSummaryRight(self->handler)) Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_group_summary_right(XLPySheet *self, PyObject *args)
{
	PyObject *right;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &right)) return NULL;

	xlSheetSetGroupSummaryRight(self->handler, PyObject_IsTrue(right));
	Py_RETURN_NONE;
}

static PyObject *
clear(XLPySheet *self, PyObject *args)
{
	int rowFirst, rowLast, colFirst, colLast;
	if(!PyArg_ParseTuple(args, "iiii",
		&rowFirst, &rowLast, &colFirst, &colLast)) return NULL;

	xlSheetClear(self->handler, rowFirst, rowLast, colFirst, colLast);
	Py_RETURN_NONE;
}

static PyObject *
insert_row(XLPySheet *self, PyObject *args)
{
    int first, last;
    if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

    if(xlSheetInsertRow(self->handler, first, last))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
insert_col(XLPySheet *self, PyObject *args)
{
    int first, last;
    if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

    if(xlSheetInsertCol(self->handler, first, last))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
remove_row(XLPySheet *self, PyObject *args)
{
    int first, last;
    if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

    if(xlSheetRemoveRow(self->handler, first, last))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
remove_col(XLPySheet *self, PyObject *args)
{
    int first, last;
    if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

    if(xlSheetRemoveCol(self->handler, first, last))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
copy_cell(XLPySheet *self, PyObject *args)
{
    int rowSrc, colSrc, rowDst, colDst;
    if(!PyArg_ParseTuple(args, "iiii", &rowSrc, &colSrc, &rowDst, &colDst))
        return NULL;

    if(xlSheetCopyCell(self->handler, rowSrc, colSrc, rowDst, colDst))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
first_row(XLPySheet *self)
{
    return Py_BuildValue("i", xlSheetFirstRow(self->handler));
}

static PyObject *
last_row(XLPySheet *self)
{
    return Py_BuildValue("i", xlSheetLastRow(self->handler));
}

static PyObject *
first_col(XLPySheet *self)
{
    return Py_BuildValue("i", xlSheetFirstCol(self->handler));
}

static PyObject *
last_col(XLPySheet *self)
{
    return Py_BuildValue("i", xlSheetLastCol(self->handler));
}

static PyObject *
display_gridlines(XLPySheet *self)
{
	if(xlSheetDisplayGridlines(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_display_gridlines(XLPySheet *self, PyObject *args)
{
	PyObject *show;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &show)) return NULL;

	xlSheetSetDisplayGridlines(self->handler, PyObject_IsTrue(show));
	Py_DECREF(show);
        Py_RETURN_NONE;
}

static PyObject *
print_gridlines(XLPySheet *self)
{
	if(xlSheetPrintGridlines(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_print_gridlines(XLPySheet *self, PyObject *args)
{
	PyObject *print;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &print)) return NULL;

	xlSheetSetPrintGridlines(self->handler, PyObject_IsTrue(print));
	Py_DECREF(print);
        Py_RETURN_NONE;
}

static PyObject *
zoom(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetZoom(self->handler));
}

static PyObject *
set_zoom(XLPySheet *self, PyObject *args)
{
	int zoom;
	if(!PyArg_ParseTuple(args, "i", &zoom)) return NULL;

	xlSheetSetZoom(self->handler, zoom);
	Py_RETURN_NONE;
}

static PyObject *
get_print_fit(XLPySheet *self)
{
	int wPages, hPages;
	xlSheetGetPrintFit(self->handler, &wPages, &hPages);
	return Py_BuildValue("(ii)", wPages, hPages);
}

static PyObject *
set_print_fit(XLPySheet *self, PyObject *args)
{
	int wPages, hPages;
	if(!PyArg_ParseTuple(args, "ii", &wPages, &hPages)) return NULL;

	xlSheetSetPrintFit(self->handler, wPages, hPages);
	Py_RETURN_NONE;
}

static PyObject *
landscape(XLPySheet *self)
{
	if(xlSheetLandscape(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_landscape(XLPySheet *self, PyObject *args)
{
	PyObject *landscape;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &landscape)) return NULL;

	xlSheetSetLandscape(self->handler, PyObject_IsTrue(landscape));
	Py_DECREF(landscape);

	Py_RETURN_NONE;
}

static PyObject *
paper(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetPaper(self->handler));
}

static PyObject *
set_paper(XLPySheet *self, PyObject *args)
{
	int paper;
	if(!PyArg_ParseTuple(args, "i", &paper)) return NULL;

	xlSheetSetPaper(self->handler, paper);
	Py_RETURN_NONE;
}

static PyObject *
header(XLPySheet *self)
{
	return Py_BuildValue("s", xlSheetHeader(self->handler));
}

static PyObject *
set_header(XLPySheet *self, PyObject *args)
{
	const char *header;
	double margin;

	if(!PyArg_ParseTuple(args, "sd", &header, &margin)) return NULL;

	if(xlSheetSetHeader(self->handler, header, margin))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
header_margin(XLPySheet *self)
{
	return Py_BuildValue("d", xlSheetHeaderMargin(self->handler));
}

static PyObject *
footer(XLPySheet *self)
{
	return Py_BuildValue("s", xlSheetFooter(self->handler));
}

static PyObject *
set_footer(XLPySheet *self, PyObject *args)
{
	const char *footer;
	double margin;

	if(!PyArg_ParseTuple(args, "sd", &footer, &margin)) return NULL;

	if(xlSheetSetFooter(self->handler, footer, margin))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
footer_margin(XLPySheet *self)
{
	return Py_BuildValue("d", xlSheetFooterMargin(self->handler));
}

static PyObject *
h_center(XLPySheet *self)
{
	if(xlSheetHCenter(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_h_center(XLPySheet *self, PyObject *args)
{
	PyObject *bool;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &bool)) return NULL;

	xlSheetSetHCenter(self->handler, PyObject_IsTrue(bool));
	Py_RETURN_NONE;
}

static PyObject *
v_center(XLPySheet *self)
{
	if(xlSheetVCenter(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_v_center(XLPySheet *self, PyObject *args)
{
	PyObject *bool;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &bool)) return NULL;

	xlSheetSetVCenter(self->handler, PyObject_IsTrue(bool));
	Py_RETURN_NONE;
}

static PyObject *
generic_margin(XLPySheet *self, int pos)
{
	double margin = -1;
	switch(pos) {
		case LEFT:
			margin = xlSheetMarginLeft(self->handler);
			break;
		case RIGHT:
			margin = xlSheetMarginRight(self->handler);
			break;
		case TOP:
			margin = xlSheetMarginTop(self->handler);
			break;
		case BOTTOM:
			margin = xlSheetMarginBottom(self->handler);
			break;
	}

	return Py_BuildValue("d", margin);
}

static PyObject *
generic_set_margin(XLPySheet *self, PyObject *args, int pos)
{
	double margin;
	if(!PyArg_ParseTuple(args, "d", &margin)) return NULL;

	switch(pos) {
		case LEFT:
			xlSheetSetMarginLeft(self->handler, margin);
			break;
		case RIGHT:
			xlSheetSetMarginRight(self->handler, margin);
			break;
		case TOP:
			xlSheetSetMarginTop(self->handler, margin);
			break;
		case BOTTOM:
			xlSheetSetMarginBottom(self->handler, margin);
			break;
	}

	Py_RETURN_NONE;
}

static PyObject *
margin_left(XLPySheet *self) { return generic_margin(self, LEFT); }

static PyObject *
margin_right(XLPySheet *self) { return generic_margin(self, RIGHT); }

static PyObject *
margin_top(XLPySheet *self) { return generic_margin(self, TOP); }

static PyObject *
margin_bottom(XLPySheet *self) { return generic_margin(self, BOTTOM); }

static PyObject *
set_margin_left(XLPySheet *self, PyObject *args)
{
	return generic_set_margin(self, args, LEFT);
}

static PyObject *
set_margin_right(XLPySheet *self, PyObject *args)
{
	return generic_set_margin(self, args, RIGHT);
}

static PyObject *
set_margin_top(XLPySheet *self, PyObject *args)
{
	return generic_set_margin(self, args, TOP);
}

static PyObject *
set_margin_bottom(XLPySheet *self, PyObject *args)
{
	return generic_set_margin(self, args, BOTTOM);
}

static PyObject *
print_row_col(XLPySheet *self)
{
	if(xlSheetPrintRowCol(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_print_row_col(XLPySheet *self, PyObject *args)
{
	PyObject *print;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &print)) return NULL;

	xlSheetSetPrintRowCol(self->handler, PyObject_IsTrue(print));
	Py_RETURN_NONE;
}

static PyObject *
set_printed_repeated_rows(XLPySheet *self, PyObject *args)
{
	int first, last;
	if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

	xlSheetSetPrintRepeatRows(self->handler, first, last);
	Py_RETURN_NONE;
}

static PyObject *
set_printed_repeated_cols(XLPySheet *self, PyObject *args)
{
	int first, last;
	if(!PyArg_ParseTuple(args, "ii", &first, &last)) return NULL;

	xlSheetSetPrintRepeatCols(self->handler, first, last);
	Py_RETURN_NONE;
}

static PyObject *
set_print_area(XLPySheet *self, PyObject *args)
{
	int rowFirst, rowLast, colFirst, colLast;
	if(!PyArg_ParseTuple(args, "iiii",
				&rowFirst, &rowLast, &colFirst, &colLast)) return NULL;

	xlSheetSetPrintArea(self->handler, rowFirst, rowLast, colFirst, colLast);
	Py_RETURN_NONE;
}


static PyObject *
clear_print_repeats(XLPySheet *self)
{
    xlSheetClearPrintRepeats(self->handler);
    Py_RETURN_NONE;
}

static PyObject *
clear_print_area(XLPySheet *self)
{
    xlSheetClearPrintArea(self->handler);
    Py_RETURN_NONE;
}

static PyObject *
get_named_range(XLPySheet *self, PyObject *args)
{
	const char *name;
	int scopeId;
	if(!PyArg_ParseTuple(args, "si", &name, &scopeId)) return NULL;

	int rowFirst, rowLast, colFirst, colLast, hidden;
	if(!xlSheetGetNamedRange(self->handler, name, &rowFirst, &rowLast,
		&colFirst, &colLast, scopeId, &hidden)) Py_RETURN_NONE;

	return Py_BuildValue("(iiiii)", rowFirst, rowLast, colFirst, colLast, hidden);
}

static PyObject *
set_named_range(XLPySheet *self, PyObject *args)
{
	const char *name;
	int rowFirst, rowLast, colFirst, colLast, scopeId;
	if(!PyArg_ParseTuple(args, "siiiii", &name, &rowFirst, &rowLast,
		&colFirst, &colLast, &scopeId)) return NULL;

	int r = xlSheetSetNamedRange(self->handler, name, rowFirst, rowLast,
		colFirst, colLast, scopeId);

	if(!r) Py_RETURN_NONE;
	return Py_BuildValue("i", r);
}

static PyObject *
del_named_range(XLPySheet *self, PyObject *args)
{
	const char *name;
        int scopeId;
	if(!PyArg_ParseTuple(args, "si", &name, &scopeId)) return NULL;

	if(xlSheetDelNamedRange(self->handler, name, scopeId)) Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
named_range_size(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetNamedRangeSize(
		self->handler)
	);
}

static PyObject *
named_range(XLPySheet *self, PyObject *args)
{
	int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;

	int rowFirst, rowLast, colFirst, colLast, scopeId, hidden;
	const char *range = xlSheetNamedRange(self->handler, index,
		&rowFirst, &rowLast, &colFirst, &colLast, &scopeId, &hidden);

	return Py_BuildValue("(siiiiii)", range, rowFirst, rowLast, colFirst, colLast, scopeId, hidden);
}

static PyObject *
set_name(XLPySheet *self, PyObject *args)
{
    const char *name;
    if(!PyArg_ParseTuple(args, "s", &name)) {
        return NULL;
    }

    xlSheetSetName(self->handler, name);
    Py_RETURN_NONE;
}

static PyObject *
protect(XLPySheet *self)
{
	if(xlSheetProtect(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_protect(XLPySheet *self, PyObject *args)
{
	PyObject *protect;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &protect)) return NULL;

	xlSheetSetProtect(self->handler, PyObject_IsTrue(protect));
	Py_RETURN_NONE;
}

static PyObject *
hidden(XLPySheet *self)
{
	return Py_BuildValue("i", xlSheetHidden(self->handler));
}

static PyObject *
set_hidden(XLPySheet *self, PyObject *args)
{
	int hidden;
	if(!PyArg_ParseTuple(args, "i", &hidden)) return NULL;

	return Py_BuildValue("i", xlSheetSetHidden(self->handler, hidden));
}

static PyObject *
get_top_left_view(XLPySheet *self)
{
	int row, col;
	xlSheetGetTopLeftView(self->handler, &row, &col);
	return Py_BuildValue("(ii)", row, col);
}


static PyObject *
addr_to_row_col(XLPySheet *self, PyObject *args)
{
	const char *addr;
	if(!PyArg_ParseTuple(args, "s", &addr)) return NULL;

	int row, col, rowRelative, colRelative;
	xlSheetAddrToRowCol(self->handler, addr, &row, &col, &rowRelative,
		&colRelative);

	return Py_BuildValue("(iiii)", row, col, rowRelative, colRelative);
}

static PyObject *
row_col_to_addr(XLPySheet *self, PyObject *args)
{
	int row, col, rowRelative, colRelative;
	if(!PyArg_ParseTuple(args, "iiii", &row, &col, &rowRelative, &colRelative))
		return NULL;

	return Py_BuildValue("s",
		xlSheetRowColToAddr(self->handler, row, col, rowRelative, colRelative)
	);
}

static PyMethodDef methods[] = {
    {"cellType", (PyCFunction) cell_type, METH_VARARGS,
        "Returns cell's type."},
    {"isFormula", (PyCFunction) is_formula, METH_VARARGS,
        "Checks that cell contains a formula."},
	{"cellFormat", (PyCFunction) cell_format, METH_VARARGS,
		"Returns cell's format. It can be changed by user."},
	{"setCellFormat", (PyCFunction) set_cell_format, METH_VARARGS,
		"Sets cell's format."},
	{"readStr", (PyCFunction) read_str, METH_VARARGS,
		"Reads a string and its format from cell. "
		"Returns a (text, format) tuple, "
		"Format will be None if specified cell doesn't contain string or error occurs."},
	{"writeStr", (PyCFunction) write_str, METH_VARARGS,
		"Writes a string into cell with specified format (if present). Returns False if error occurs."},
	{"readNum", (PyCFunction) read_num, METH_VARARGS,
		"Reads a number or date/time and its format from cell. "
		"Use Book::dateUnpack() for extract date/time parts. "
		"Returns a tuple with (num, format)."},
    {"writeNum", (PyCFunction) write_num, METH_VARARGS,
        "Writes a string into cell with specified format. "
        "If format is not present then format is ignored. "
        "Returns False if error occurs."},
	{"readBool", (PyCFunction) read_bool, METH_VARARGS,
		"Reads a bool value and its format from cell. "
		"If format is None then error occurs. "
		"Returns a tuple with (num, format)."},
	{"writeBool", (PyCFunction) write_bool, METH_VARARGS,
		"Writes a bool value into cell with specified format. "
		"If format is None then format is ignored. "
		"Returns False if error occurs."},
	{"readBlank", (PyCFunction) read_blank, METH_VARARGS,
		"Reads format from blank cell. Returns False if specified cell isn't blank or error occurs."},
	{"writeBlank", (PyCFunction) write_blank, METH_VARARGS,
		"Writes blank cell with specified format."},
	{"readFormula", (PyCFunction) read_formula, METH_VARARGS,
		"Reads a formula and its format from cell. "
		"Returns None if specified cell doesn't contain formula or error occurs."},
	{"writeFormula", (PyCFunction) write_formula, METH_VARARGS,
		"Writes a formula into cell with specified format. "
		"If format equals None then format is ignored. "
		"Returns False if error occurs."},
	{"readComment", (PyCFunction) read_comment, METH_VARARGS,
		"Reads a comment from specified cell."},
	{"writeComment", (PyCFunction) write_comment, METH_VARARGS,
		"Writes a comment to the cell. Parameters:\n"
		"(row, col) - cell's position;\n"
		"value - comment string;\n"
		"author - author string;\n"
		"width - width of text box in pixels;\n"
		"height - height of text box in pixels."},
	{"isDate", (PyCFunction) is_date, METH_VARARGS,
		"Checks that cell contains a date or time value."},
	{"readError", (PyCFunction) read_error, METH_VARARGS,
		"Reads error from cell."},
	{"colWidth", (PyCFunction) col_width, METH_VARARGS,
		"Returns column width."},
	{"rowHeight", (PyCFunction) row_height, METH_VARARGS,
		"Returns row height."},
	{"setCol", (PyCFunction) set_col, METH_KEYWORDS,
		"Sets column width and format for all columns from colFirst to colLast. "
		"Column width measured as the number of characters of the maximum digit width of the numbers 0, 1, 2, ..., 9 as rendered in the normal style's font. "
		"If format equals None then format is ignored. "
		"Columns may be hidden. Returns False if error occurs"},
	{"setRow", (PyCFunction) set_row, METH_KEYWORDS,
		"Sets row height and format. Row height measured in point size. "
		"If format equals None then format is ignored. "
		"Row may be hidden. Returns False if error occurs"},
	{"rowHidden", (PyCFunction) row_hidden, METH_VARARGS,
		"Returns whether row is hidden."},
	{"setRowHidden", (PyCFunction) set_row_hidden, METH_VARARGS,
		"Hides row."},
	{"colHidden", (PyCFunction) col_hidden, METH_VARARGS,
		"Returns whether col is hidden."},
	{"setColHidden", (PyCFunction) set_col_hidden, METH_VARARGS,
		"Hides col."},
	{"getMerge", (PyCFunction) get_merge, METH_VARARGS,
		"Gets merged cells for cell at row, col. "
		"Result is a tuple of rowFirst, rowLast, colFirst, colLast. "
		"Returns None if error occurs."},
	{"setMerge", (PyCFunction) set_merge, METH_VARARGS,
		"Sets merged cells for range: rowFirst - rowLast, colFirst - colLast. "
		"Returns False if error occurs."},
	{"delMerge", (PyCFunction) del_merge, METH_VARARGS,
		"Removes merged cells. Returns False if error occurs."},
	{"pictureSize", (PyCFunction) picture_size, METH_NOARGS,
		"Returns a number of pictures in this worksheet."},
	{"getPicture", (PyCFunction) get_picture, METH_VARARGS,
		"Returns a workbook picture index at position index in worksheet. "
		"Returns a tuple with the following values: \n"
		"(rowTop, colLeft) - top left position of picture;\n"
		"(rowBottom, colRight) - bottom right position of picture;\n"
		"width - width of picture in pixels; \n"
		"height - height of picture in pixels; \n"
		"offset_x - horizontal offset of picture in pixels; \n"
		"offset_y - vertical offset of picture in pixels. "
		"Use Book::getPicture() for extracting binary data of picture by workbook picture index. "
		"Returns None if error occurs."},
    {"setPicture", (PyCFunction) set_picture, METH_VARARGS,
        "Sets a picture with pictureId identifier at position row and col with scale factor and offsets in pixels. "
        "Use Book::addPicture() for getting picture identifier."},
    {"setPicture2", (PyCFunction) set_picture_2, METH_VARARGS,
        "Sets a picture with pictureId identifier at position row and col with custom size and offsets in pixels. "
        "Use Book::addPicture() for getting a picture identifier."},
    {"getHorPageBreak", (PyCFunction) get_hor_page_break, METH_VARARGS,
    	"Returns row with horizontal page break at position index."},
    {"getHorPageBreakSize", (PyCFunction) get_hor_page_break_size, METH_NOARGS,
    	"Returns a number of horizontal page breaks in the sheet."},
    {"getVerPageBreak", (PyCFunction) get_ver_page_break, METH_VARARGS,
    	"Returns column with vertical page break at position index."},
    {"getVerPageBreakSize", (PyCFunction) get_ver_page_break_size, METH_NOARGS,
    	"Returns a number of vertical page breaks in the sheet."},
    {"setHorPageBreak", (PyCFunction) set_hor_page_break, METH_VARARGS,
    	"Sets/removes a horizontal page break (sets if True, removes if False). "
    	"Returns False if error occurs."},
    {"setVerPageBreak", (PyCFunction) set_ver_page_break, METH_VARARGS,
    	"Sets/removes a vertical page break (sets if True, removes if False). "
    	"Returns False if error occurs."},
    {"split", (PyCFunction) split, METH_VARARGS,
        "Splits a sheet at position (row, col)."},
    {"groupRows", (PyCFunction) group_rows, METH_VARARGS,
        "Groups rows from rowFirst to rowLast. Returns False if error occurs."},
	{"groupCols", (PyCFunction) group_cols, METH_VARARGS,
		"Groups columns from colFirst to colLast. Returns False if error occurs."},
	{"groupSummaryBelow", (PyCFunction) group_summary_below, METH_NOARGS,
		"Returns whether grouping rows summary is below. "
		"Returns True if summary is below and False if isn't."},
	{"setGroupSummaryBelow", (PyCFunction) set_group_summary_below, METH_VARARGS,
		"Sets a flag of grouping rows summary: True - below, False - above."},
	{"groupSummaryRight", (PyCFunction) group_summary_right, METH_NOARGS,
		"Returns whether grouping columns summary is right. "
		"Returns True if summary is right and False if isn't."},
	{"setGroupSummaryRight", (PyCFunction) set_group_summary_right, METH_VARARGS,
		"Sets a flag of grouping columns summary: True - right, False - left."},
	{"clear", (PyCFunction) clear, METH_VARARGS,
		"Clears cells in specified area."},
    {"insertRow", (PyCFunction) insert_row, METH_VARARGS,
        "Inserts rows from rowFirst to rowLast."
        "Returns False if error occurs."},
    {"insertCol", (PyCFunction) insert_col, METH_VARARGS,
        "Inserts cols from colFirst to colLast."
        "Returns False if error occurs."},
    {"removeRow", (PyCFunction) remove_row, METH_VARARGS,
        "Removes rows from rowFirst to rowLast."
        "Returns False if error occurs."},
    {"removeCol", (PyCFunction) remove_col, METH_VARARGS,
        "Removes cols from colFirst to colLast."
        "Returns False if error occurs."},
    {"copyCell", (PyCFunction) copy_cell, METH_VARARGS,
        "Copies cell with format from (rowSrc, colSrc) to (rowDst, colDst). "
        "Returns False if error occurs."},
    {"firstRow", (PyCFunction) first_row, METH_NOARGS,
        "Returns the first row in the sheet that contains a used cell."},
    {"lastRow", (PyCFunction) last_row, METH_NOARGS,
        "Returns the zero-based index of the row after the last row in the sheet that contains a used cell."},
    {"firstCol", (PyCFunction) first_col, METH_NOARGS,
        "Returns the first column in the sheet that contains a used cell."},
    {"lastCol", (PyCFunction) last_col, METH_NOARGS,
        "Returns the zero-based index of the column after the last column in the sheet that contains a used cell."},
	{"displayGridlines", (PyCFunction) display_gridlines, METH_NOARGS,
		"Returns whether the gridlines are displayed. "
		"Returns True if gridlines are displayed and False if aren't."},
	{"setDisplayGridlines", (PyCFunction) set_display_gridlines, METH_VARARGS,
		"Sets gridlines for displaying, "
		"True  - gridlines are displayed, "
		"False - gridlines aren't displayed"},
	{"printGridlines", (PyCFunction) print_gridlines, METH_NOARGS,
		"Returns whether the gridlines are printer. "
		"Returns True if gridlines are printer and False if aren't."},
	{"setPrintGridlines", (PyCFunction) set_print_gridlines, METH_VARARGS,
		"Sets gridlines for printing, "
		"True  - gridlines are printed, "
		"False - gridlines aren't printed"},
	{"zoom", (PyCFunction) zoom, METH_NOARGS,
		"Returns the scaling factor for printing as a percentage."},
	{"setZoom", (PyCFunction) set_zoom, METH_VARARGS,
		"Sets the scaling factor for printing as a percentage."},
	{"getPrintFit", (PyCFunction) get_print_fit, METH_NOARGS,
		"Returns whether fit to page option is enabled as a tuple of:\n"
		"wPages - number of pages the sheet width is fit to;\n"
		"hPages - number of pages the sheet height is fit to"},
	{"setPrintFit", (PyCFunction) set_print_fit, METH_VARARGS,
		"Fits sheet width and sheet height to wPages and hPages respectively."},
	{"landscape", (PyCFunction) landscape, METH_NOARGS,
		"Returns a page orientation mode, "
		"True - landscape mode, False - portrait mode."},
	{"setLandscape", (PyCFunction) set_landscape, METH_VARARGS,
		"Sets landscape or portrait mode for printing, "
		"True - pages are printed using landscape mode, "
		"False - pages are printed using portrait mode"},
	{"paper", (PyCFunction) paper, METH_NOARGS,
		"Retrurns the paper size."},
	{"setPaper", (PyCFunction) set_paper, METH_VARARGS,
		"Sets the paper size."},
	{"header", (PyCFunction) header, METH_NOARGS,
		"Returns the header text of the sheet when printed."},
	{"setHeader", (PyCFunction) set_header, METH_VARARGS,
		"Sets the header text of the sheet when printed. "
		"The text appears at the top of every page when printed. "
		"The length of the text must be less than or equal to 255. "
		"The header text can contain special commands, for example a placeholder for the page number, "
		"current date or text formatting attributes. "
		"Special commands are represented by single letter with a leading ampersand (\"&\"). "
		"Margin is specified in inches."},
	{"headerMargin", (PyCFunction) header_margin, METH_NOARGS,
		"Returns the header margin in inches."},
	{"footer", (PyCFunction) footer, METH_NOARGS,
		"Returns the footer text of the sheet when printed."},
	{"setFooter", (PyCFunction) set_footer, METH_VARARGS,
		"Sets the footer text for the sheet when printed. "
		"The footer text appears at the bottom of every page when printed. "
		"The length of the text must be less than or equal to 255. "
		"The footer text can contain special commands, "
		"for example a placeholder for the page number, "
		"current date or text formatting attributes. "
		"See Sheet::SetHeader() for details. "
		"Margin is specified in inches."},
	{"footerMargin", (PyCFunction) footer_margin, METH_NOARGS,
		"Returns the footer margin in inches."},
	{"hCenter", (PyCFunction) h_center, METH_NOARGS,
		"Returns whether the sheet is centered horizontally when printed"},
	{"setHCenter", (PyCFunction) set_h_center, METH_VARARGS,
		"Sets a flag that the sheet is centered horizontally when printed"},
	{"vCenter", (PyCFunction) v_center, METH_NOARGS,
		"Returns whether the sheet is centered vertically when printed"},
	{"setVCenter", (PyCFunction) set_v_center, METH_VARARGS,
		"Sets a flag that the sheet is centered vertically when printed"},
	{"marginLeft", (PyCFunction) margin_left, METH_NOARGS,
		"Returns the left margin of the sheet in inches."},
	{"setMarginLeft", (PyCFunction) set_margin_left, METH_VARARGS,
		"Sets the left margin of the sheet in inches."},
	{"marginRight", (PyCFunction) margin_right, METH_NOARGS,
		"Returns the Right margin of the sheet in inches."},
	{"setMarginRight", (PyCFunction) set_margin_right, METH_VARARGS,
		"Sets the right margin of the sheet in inches."},
	{"marginTop", (PyCFunction) margin_top, METH_NOARGS,
		"Returns the top margin of the sheet in inches."},
	{"setMarginTop", (PyCFunction) set_margin_top, METH_VARARGS,
		"Sets the top margin of the sheet in inches."},
	{"marginBottom", (PyCFunction) margin_bottom, METH_NOARGS,
		"Returns the bottom margin of the sheet in inches."},
	{"setMarginBottom", (PyCFunction) set_margin_bottom, METH_VARARGS,
		"Sets the bottom margin of the sheet in inches."},
	{"printRowCol", (PyCFunction) print_row_col, METH_NOARGS,
		"Returns whether the row and column headers are printed."},
	{"setPrintRowCol", (PyCFunction) set_print_row_col, METH_VARARGS,
		"Sets a flag that the row and column headers are printed"},
	{"setPrintRepeatedRows", (PyCFunction) set_printed_repeated_rows, METH_VARARGS,
		"Sets repeated rows on each page from rowFirst to rowLast"},
	{"setPrintRepeatedCols", (PyCFunction) set_printed_repeated_cols, METH_VARARGS,
		"Sets repeated cols on each page from rowFirst to rowLast"},
	{"setPrintArea", (PyCFunction) set_print_area, METH_VARARGS,
		"Sets the print area."},

    {"clearPrintRepeats", (PyCFunction) clear_print_repeats, METH_NOARGS,
        "Clears repeated rows and columns on each page."},
    {"clearPrintArea", (PyCFunction) clear_print_area, METH_NOARGS,
        "Clears the print area."},
	{"getNamedRange", (PyCFunction) get_named_range, METH_VARARGS,
		"Gets the named range coordianates by name. "
		"Returns None if specified named range isn't found or error occurs."},
	{"setNamedRange", (PyCFunction) set_named_range, METH_VARARGS,
		"Sets the named range. Returns None if error occurs."},
	{"delNamedRange", (PyCFunction) del_named_range, METH_VARARGS,
		"Deletes the named range by name. "
		"Returns False if error occurs."},
	{"namedRangeSize", (PyCFunction) named_range_size, METH_NOARGS,
		"Returns the number of named ranges in the sheet."},
	{"namedRange", (PyCFunction) named_range, METH_VARARGS,
		"Gets the named range coordianates by index."},
    {"setName", (PyCFunction) set_name, METH_VARARGS,
        "Sets the name of the sheet."},
	{"protect", (PyCFunction) protect, METH_NOARGS,
		"Returns whether sheet is protected"},
	{"setProtect", (PyCFunction) set_protect, METH_VARARGS,
		"Protects or unprotects the sheet"},
	{"hidden", (PyCFunction) hidden, METH_NOARGS,
		"Returns whether sheet is hidden."},
	{"setHidden", (PyCFunction) set_hidden, METH_VARARGS,
		"Hides/unhides the sheet. Returns False if error occurs. "
		"SHEETSTATE_VISIBLE: sheet is visible\n"
		"SHEETSTATE_HIDDEN:	sheet is hidden, but can be shown via the user interface\n"
		"SHEETSTATE_VERYHIDDEN: sheet is hidden and cannot be shown in the user interface"},
	{"getTopLeftView", (PyCFunction) get_top_left_view, METH_NOARGS,
		"Extracts the first visible row and the leftmost visible column of the sheet."},
	{"addrToRowCol", (PyCFunction) addr_to_row_col, METH_VARARGS,
		"Converts a cell reference to row and column."},
	{"rowColToAddr", (PyCFunction) row_col_to_addr, METH_VARARGS,
		"Converts row and column to a cell reference."},
	{NULL}
};

PyTypeObject XLPySheetType = {
   PyObject_HEAD_INIT(NULL)
   0,                         /* ob_size */
   "XLPySheet",               /* tp_name */
   sizeof(XLPySheet),         /* tp_basicsize */
   0,                         /* tp_itemsize */
   (destructor)dealloc,/* tp_dealloc */
   0,                         /* tp_print */
   0,                         /* tp_getattr */
   0,                         /* tp_setattr */
   0,                         /* tp_compare */
   0,                         /* tp_repr */
   0,                         /* tp_as_number */
   0,                         /* tp_as_sequence */
   0,                         /* tp_as_mapping */
   0,                         /* tp_hash */
   0,                         /* tp_call */
   0,                         /* tp_str */
   0,                         /* tp_getattro */
   0,                         /* tp_setattro */
   0,                         /* tp_as_buffer */
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags*/
   "XLPy Sheet",                 /* tp_doc */
   0,                         /* tp_traverse */
   0,                         /* tp_clear */
   0,                         /* tp_richcompare */
   0,                         /* tp_weaklistoffset */
   0,                         /* tp_iter */
   0,                         /* tp_iternext */
   methods,            /* tp_methods */
   0,                         /* tp_members */
   0,                         /* tp_getset */
   0,                         /* tp_base */
   0,                         /* tp_dict */
   0,                         /* tp_descr_get */
   0,                         /* tp_descr_set */
   0,                         /* tp_dictoffset */
   (initproc)init,     /* tp_init */
   0,                         /* tp_alloc */
   0,                         /* tp_new */
};
