#include <Python.h>
#include <libxl.h>

#include "format.h"
#include "font.h"

extern PyTypeObject XLPyFontType;

typedef void(op_t)(FormatHandle, int);

static int
init(XLPyFormat *self)
{
    return 0;
}

static void
dealloc(XLPyFormat *self)
{
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
generic_set(XLPyFormat *self, PyObject *args, op_t op)
{
	int val;
	PyArg_ParseTuple(args, "i", &val);
	op(self->handler, val);
	Py_RETURN_NONE;
}

static PyObject *
font(XLPyFormat *self)
{
	FontHandle font = xlFormatFont(self->handler);
	if(!font) Py_RETURN_NONE;

	XLPyFont *obj = PyObject_New(XLPyFont, &XLPyFontType);
	obj->handler = font;
	return (PyObject *)obj;
}

static PyObject *
set_font(XLPyFormat *self, PyObject *args)
{
	PyObject *font;
	if(!PyArg_ParseTuple(args, "O!", &XLPyFontType, &font)) return NULL;

	if(xlFormatSetFont(self->handler, ((XLPyFont *)font)->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
num_format(XLPyFormat *self)
{
    return Py_BuildValue("i",
            xlFormatNumFormat(self->handler));
}

static PyObject *
set_num_format(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetNumFormat);
}

static PyObject *
align_h(XLPyFormat *self)
{
	return Py_BuildValue("i", xlFormatAlignH(self->handler));
}

static PyObject *
set_align_h(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetAlignH);
}

static PyObject *
align_v(XLPyFormat *self)
{
	return Py_BuildValue("i", xlFormatAlignV(self->handler));
}

static PyObject *
set_align_v(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetAlignV);
}

static PyObject *
wrap(XLPyFormat *self)
{
	if(xlFormatWrap(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_wrap(XLPyFormat *self, PyObject *args)
{
	PyObject *wrap;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &wrap)) return NULL;

	xlFormatSetWrap(self->handler, PyObject_IsTrue(wrap));
	Py_RETURN_NONE;
}

static PyObject *
rotation(XLPyFormat *self)
{
	return Py_BuildValue("i", xlFormatRotation(self->handler));
}

static PyObject *
set_rotation(XLPyFormat *self, PyObject *args)
{
	int rotation;
	if(!PyArg_ParseTuple(args, "i", &rotation)) return NULL;

	return Py_BuildValue("i", xlFormatSetRotation(self->handler, rotation));
}

static PyObject *
indent(XLPyFormat *self)
{
	return Py_BuildValue("i", xlFormatIndent(self->handler));
}

static PyObject *
set_indent(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetIndent);
}


static PyObject *
shrink_to_fit(XLPyFormat *self)
{
	if(xlFormatShrinkToFit(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_shrink_to_fit(XLPyFormat *self, PyObject *args)
{
	PyObject *shrink;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &shrink)) return NULL;
	xlFormatSetShrinkToFit(self->handler, PyObject_IsTrue(shrink));
	Py_RETURN_NONE;
}

static PyObject *
set_border(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetBorder);
}


#define GET_BORDER(name, fn) static PyObject *\
	border_##name(XLPyFormat *self) {\
		return Py_BuildValue("i", fn(self->handler));\
	}

#define SET_BORDER(name, fn) static PyObject *\
	set_border_##name(XLPyFormat *self, PyObject *args) {\
		return generic_set(self, args, fn);\
	}

GET_BORDER(left,           xlFormatBorderLeft)
GET_BORDER(right,          xlFormatBorderRight)
GET_BORDER(top,            xlFormatBorderTop)
GET_BORDER(bottom,         xlFormatBorderBottom)
GET_BORDER(left_color,     xlFormatBorderLeftColor)
GET_BORDER(right_color,    xlFormatBorderRightColor)
GET_BORDER(top_color,      xlFormatBorderTopColor)
GET_BORDER(bottom_color,   xlFormatBorderBottomColor)
GET_BORDER(diagonal,       xlFormatBorderDiagonal)
GET_BORDER(diagonal_color, xlFormatBorderDiagonalColor)

SET_BORDER(color,          xlFormatSetBorderColor)
SET_BORDER(left,           xlFormatSetBorderLeft)
SET_BORDER(right,          xlFormatSetBorderRight)
SET_BORDER(top,            xlFormatSetBorderTop)
SET_BORDER(bottom,         xlFormatSetBorderBottom)
SET_BORDER(left_color,     xlFormatSetBorderLeftColor)
SET_BORDER(right_color,    xlFormatSetBorderRightColor)
SET_BORDER(top_color,      xlFormatSetBorderTopColor)
SET_BORDER(bottom_color,   xlFormatSetBorderBottomColor)
SET_BORDER(diagonal,       xlFormatSetBorderDiagonal)
SET_BORDER(diagonal_color, xlFormatSetBorderDiagonalColor)

static PyObject *
fill_pattern(XLPyFormat *self)
{
	return Py_BuildValue("i", xlFormatFillPattern(self->handler));
}

static PyObject *
set_fill_pattern(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetFillPattern);
}

static PyObject *
pattern_foreground_color(XLPyFormat *self)
{
	return Py_BuildValue("i",
		xlFormatPatternForegroundColor(self->handler)
	);
}

static PyObject *
set_pattern_foreground_color(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetPatternForegroundColor);
}

static PyObject *
pattern_background_color(XLPyFormat *self)
{
	return Py_BuildValue("i",
		xlFormatPatternBackgroundColor(self->handler)
	);
}

static PyObject *
set_pattern_background_color(XLPyFormat *self, PyObject *args)
{
	return generic_set(self, args, xlFormatSetPatternBackgroundColor);
}

static PyObject *
locked(XLPyFormat *self)
{
	if(xlFormatLocked(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
set_locked(XLPyFormat *self, PyObject *args)
{
	PyObject *locked;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &locked)) return NULL;

	xlFormatSetLocked(self->handler, PyObject_IsTrue(locked));
	Py_RETURN_NONE;
}

static PyObject *
set_hidden(XLPyFormat *self, PyObject *args)
{
	PyObject *hidden;
	if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &hidden)) return NULL;

	xlFormatSetHidden(self->handler, PyObject_IsTrue(hidden));
	Py_RETURN_NONE;
}

static PyObject *
hidden(XLPyFormat *self)
{
	if(xlFormatHidden(self->handler))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyMethodDef methods[] = {
	{"font", (PyCFunction) font, METH_NOARGS,
		"Returns the handle of the current font. "
		"Returns None if error occurs."},
	{"setFont", (PyCFunction) set_font, METH_VARARGS,
		"Sets the font for the format. "
		"To create a new font use Book::addFont()"},
    {"numFormat", (PyCFunction) num_format, METH_NOARGS,
        "Returns the number format identifier."},
	{"setNumFormat", (PyCFunction) set_num_format, METH_VARARGS,
		"Sets the number format identifier. "
		"The identifier must be a valid built-in number format identifier or the identifier of a custom number format. "
		"To create a custom format use Book::AddCustomNumFormat()"},
	{"alignH", (PyCFunction) align_h, METH_NOARGS,
		"Returns the horizontal alignment."},
	{"setAlignH", (PyCFunction) set_align_h, METH_VARARGS,
		"Sets the horizontal alignment."},
	{"alignV", (PyCFunction) align_v, METH_NOARGS,
		"Returns the vertical alignment."},
	{"setAlignV", (PyCFunction) set_align_v, METH_VARARGS,
		"Sets the vertical alignment."},
	{"wrap", (PyCFunction) wrap, METH_NOARGS,
		"Returns whether the cell text is wrapped: "
		"True - wrapped, False - not wrapped"},
	{"setWrap", (PyCFunction) set_wrap, METH_VARARGS,
		"Sets the flag whether the cell text is wrapped: "
		"True - wrapped, False - not wrapped."},
	{"rotation", (PyCFunction) rotation, METH_NOARGS,
		"Returns the text rotation."},
	{"setRotation", (PyCFunction) set_rotation, METH_VARARGS,
		"Sets the text rotation."},
	{"indent", (PyCFunction) indent, METH_NOARGS,
		"Returns the text indentation level."},
	{"setIndent", (PyCFunction) set_indent, METH_VARARGS,
		"Sets the text indentation level. Must be less than or equal to 15."},
	{"shrinkToFit", (PyCFunction) shrink_to_fit, METH_NOARGS,
		"Returns whether the cell is shrink-to-fit: "
		"True - shrink-to-fit, False - not shrink-to-fit."},
	{"setShrinkToFit", (PyCFunction) set_shrink_to_fit, METH_VARARGS,
		"Sets the flag whether the cell is shrink-to-fit: "
		"False - shrink-to-fit, True - not shrink-to-fit"},

	{"setBorder", (PyCFunction) set_border, METH_VARARGS,
		"Sets the border style."},
	{"setBorderColor", (PyCFunction) set_border_color, METH_VARARGS,
		"Sets the border color"},

	{"borderLeft", (PyCFunction) border_left, METH_NOARGS,
		"Returns the left border style."},
	{"setBorderLeft", (PyCFunction) set_border_left, METH_VARARGS,
		"Sets the left border style."},

	{"borderRight", (PyCFunction) border_right, METH_NOARGS,
		"Returns the right border style."},
	{"setBorderRight", (PyCFunction) set_border_right, METH_VARARGS,
		"Sets the right border style."},

	{"borderTop", (PyCFunction) border_top, METH_NOARGS,
		"Returns the top border style."},
	{"setBorderTop", (PyCFunction) set_border_top, METH_VARARGS,
		"Sets the top border style."},

	{"borderBottom", (PyCFunction) border_bottom, METH_NOARGS,
		"Returns the bottom border style."},
	{"setBorderBottom", (PyCFunction) set_border_bottom, METH_VARARGS,
		"Sets the bottom border style."},

	{"borderLeftColor", (PyCFunction) border_left_color, METH_NOARGS,
		"Returns the color of the left border."},
	{"setBorderLeftColor", (PyCFunction) set_border_left_color, METH_VARARGS,
		"Sets the color of the left border."},

	{"borderRightColor", (PyCFunction) border_right_color, METH_NOARGS,
		"Returns the color of the right border."},
	{"setBorderRightColor", (PyCFunction) set_border_right_color, METH_VARARGS,
		"Sets the color of the right border."},

	{"borderTopColor", (PyCFunction) border_top_color, METH_NOARGS,
		"Returns the color of the top border."},
	{"setBorderTopColor", (PyCFunction) set_border_top_color, METH_VARARGS,
		"Sets the color of the top border."},

	{"borderBottomColor", (PyCFunction) border_bottom_color, METH_NOARGS,
		"Returns the color of the bottom border."},
	{"setBorderBottomColor", (PyCFunction) set_border_bottom_color, METH_VARARGS,
		"Sets the color of the bottom border."},

	{"borderDiagonal", (PyCFunction) border_diagonal, METH_NOARGS,
		"Returns the diagonal border."},
	{"setBorderDiagonal", (PyCFunction) set_border_diagonal, METH_VARARGS,
		"Sets the diagonal border."},

	{"borderDiagonalColor", (PyCFunction) border_diagonal_color, METH_NOARGS,
		"Returns the color of the diagonal border."},
	{"setBorderDiagonalColor", (PyCFunction) set_border_diagonal_color, METH_VARARGS,
		"Sets the color of the diagonal border."},

	{"fillPattern", (PyCFunction) fill_pattern, METH_NOARGS,
		"Returns the fill pattern."},
	{"setFillPattern", (PyCFunction) set_fill_pattern, METH_VARARGS,
		"Sets the fill pattern."},

	{"patternForegroundColor", (PyCFunction) pattern_foreground_color, METH_NOARGS,
		"Returns the foreground color of the fill pattern."},
	{"setPatterForegroundColor", (PyCFunction) set_pattern_foreground_color, METH_VARARGS,
		"Sets the foreground color of the fill pattern."},
	{"patternBackgroundColor", (PyCFunction) pattern_background_color, METH_NOARGS,
		"Returns the background color of the fill pattern."},
	{"setPatterBackgroundColor", (PyCFunction) set_pattern_background_color, METH_VARARGS,
		"Sets the background color of the fill pattern."},

	{"locked", (PyCFunction) locked, METH_NOARGS,
		"Returns whether the locked protection property is set to True or False"},
	{"setLocked", (PyCFunction) set_locked, METH_VARARGS,
		"Sets the locked protection property: True or False."},
	{"hidden", (PyCFunction) hidden, METH_NOARGS,
		"Returns whether the hidden protection property is set to True or False"},
	{"setHidden", (PyCFunction) set_hidden, METH_VARARGS,
		"Sets the hidden protection property: True or False"},

	{NULL}
};

PyTypeObject XLPyFormatType = {
   PyObject_HEAD_INIT(NULL)
   0,                         /* ob_size */
   "XLPyFormat",              /* tp_name */
   sizeof(XLPyFormat),        /* tp_basicsize */
   0,                         /* tp_itemsize */
   (destructor)dealloc,       /* tp_dealloc */
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
   "XLPy Format",             /* tp_doc */
   0,                         /* tp_traverse */
   0,                         /* tp_clear */
   0,                         /* tp_richcompare */
   0,                         /* tp_weaklistoffset */
   0,                         /* tp_iter */
   0,                         /* tp_iternext */
   methods,                   /* tp_methods */
   0,                         /* tp_members */
   0,                         /* tp_getset */
   0,                         /* tp_base */
   0,                         /* tp_dict */
   0,                         /* tp_descr_get */
   0,                         /* tp_descr_set */
   0,                         /* tp_dictoffset */
   (initproc)init,            /* tp_init */
   0,                         /* tp_alloc */
   0,                         /* tp_new */
};
