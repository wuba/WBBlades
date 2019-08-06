#include <Python.h>
#include <libxl.h>

#include "book.h"
#include "sheet.h"
#include "format.h"
#include "font.h"

extern PyTypeObject XLPySheetType;
extern PyTypeObject XLPyFormatType;
extern PyTypeObject XLPyFontType;

static int
init(XLPyBook *self)
{
	self->handler = xlCreateBook();
    return 0;
}

static void
dealloc(XLPyBook *self)
{
	xlBookRelease(self->handler);
	self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
load(XLPyBook *self, PyObject *args)
{
	const char* fileName;
	int size;
	PyObject *raw = NULL;
	if(!PyArg_ParseTuple(args, "s#|O!", &fileName, &size, &PyBool_Type, &raw))
		return NULL;

	if (raw && PyObject_IsTrue(raw)) {
		// fileName is treated as the buffer
		if(!xlBookLoadRaw(self->handler, fileName, size)) {
			Py_RETURN_FALSE;
		}
	}
	else {
		if(!xlBookLoad(self->handler, fileName)) {
			Py_RETURN_FALSE;
		}
	}

	Py_RETURN_TRUE;
}

static PyObject *
save(XLPyBook *self, PyObject *args)
{
	const char *fileName = NULL;
	if(!PyArg_ParseTuple(args, "|s", &fileName)) return NULL;

	// No argument, saveRaw
	if(!fileName) {
		const char *raw;
		unsigned int size;
		if(!xlBookSaveRaw(self->handler, &raw, &size)) {
			Py_RETURN_FALSE;
		}
		return Py_BuildValue("s#", raw, size);
	}

	// If argument provided, save to file
	if(!xlBookSave(self->handler, fileName)) {
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *
add_sheet(XLPyBook *self, PyObject *args)
{
	const char *name;
	PyObject *initSheet = NULL;
	if(!PyArg_ParseTuple(args, "s|O!", &name, &XLPySheetType, &initSheet))
		return NULL;
	
	SheetHandle sheet = xlBookAddSheet(self->handler, name,
			(NULL == initSheet) ? NULL : ((XLPySheet *)initSheet)->handler);

	if (!sheet) Py_RETURN_NONE;

	XLPySheet *obj = PyObject_New(XLPySheet, &XLPySheetType);
	obj->handler = sheet;
	return (PyObject *)obj;
}

static PyObject *
get_sheet(XLPyBook *self, PyObject *args)
{
	int num;
	if(!PyArg_ParseTuple(args, "i", &num))
		return NULL;

	SheetHandle sheet = xlBookGetSheet(self->handler, num);
	if (!sheet)
		Py_RETURN_NONE;

	XLPySheet *obj = PyObject_New(XLPySheet, &XLPySheetType);
	obj->handler = sheet;
	return (PyObject *)obj;
}

static PyObject *
sheet_type(XLPyBook *self, PyObject *args)
{
	int num;
	if(!PyArg_ParseTuple(args, "i", &num)) return NULL;
	return Py_BuildValue("i", xlBookSheetType(self->handler, num));
}

static PyObject *
del_sheet(XLPyBook *self, PyObject *args)
{
	int num;
	if(!PyArg_ParseTuple(args, "i", &num)) return NULL;

	if(!xlBookDelSheet(self->handler, num))
		Py_RETURN_FALSE;
	Py_RETURN_TRUE;
}

static PyObject *
sheet_count(XLPyBook *self)
{
	int count = xlBookSheetCount(self->handler);
	return Py_BuildValue("i", count);
}

static PyObject *
add_format(XLPyBook *self, PyObject *args)
{
	PyObject *initFormat = NULL;
	if(!PyArg_ParseTuple(args, "|O!", &XLPyFormatType, &initFormat)) return NULL;
	FormatHandle format = xlBookAddFormat(self->handler,
			(NULL == initFormat) ? NULL : ((XLPyFormat *)initFormat)->handler);

	if (!format) Py_RETURN_NONE;
	
	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = format;
	return (PyObject *)obj;
}

static PyObject *
add_font(XLPyBook *self, PyObject *args)
{
	PyObject *initFont = NULL;
	if(!PyArg_ParseTuple(args, "|O!", &XLPyFontType, &initFont)) return NULL;
	FontHandle font = xlBookAddFont(self->handler,
			(NULL == initFont) ? NULL : ((XLPyFont *)initFont)->handler);

	if (!font) Py_RETURN_NONE;
	
	XLPyFont *obj = PyObject_New(XLPyFont, &XLPyFontType);
	obj->handler = font;
	return (PyObject *)obj;
}

static PyObject *
active_sheet(XLPyBook *self)
{
	return Py_BuildValue("i", xlBookActiveSheet(self->handler));
}

static PyObject *
set_active_sheet(XLPyBook *self, PyObject *args)
{
	int num;
	if(!PyArg_ParseTuple(args, "i", &num)) return NULL;
	xlBookSetActiveSheet(self->handler, num);
	Py_RETURN_NONE;
}

static PyObject *
picture_size(XLPyBook *self, PyObject *args)
{
	return Py_BuildValue("i",
			xlBookPictureSize(self->handler));
}

static PyObject *
get_picture(XLPyBook *self, PyObject *args)
{
	int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;

	const char *data;
	unsigned size;
	int type = xlBookGetPicture(self->handler, index, &data, &size);
	if (-1 == type) Py_RETURN_NONE;

	return Py_BuildValue("[is#]", type, data, size);
}

static PyObject *
add_picture(XLPyBook *self, PyObject *args)
{
	const char *filename;
	if(!PyArg_ParseTuple(args, "s", &filename)) return NULL;
	return Py_BuildValue("i",
			xlBookAddPicture(self->handler, filename));
}

static PyObject *
add_picture2(XLPyBook *self, PyObject *args)
{
	const char *image;
	const int size;
	if(!PyArg_ParseTuple(args, "s#", &image, &size)) return NULL;
	return Py_BuildValue("i",
			xlBookAddPicture2(self->handler, image, size));
}

static PyObject *
default_font(XLPyBook *self)
{
    const char *name;
    int size;
    name = xlBookDefaultFont(self->handler, &size);
    if(!name) Py_RETURN_NONE;
    return Py_BuildValue("(si)", name, size);
}

static PyObject *
set_default_font(XLPyBook *self, PyObject *args)
{
    const char *name;
    int size;
    if(!PyArg_ParseTuple(args, "si", &name, &size)) return NULL;

    xlBookSetDefaultFont(self->handler, name, size);
    Py_RETURN_NONE;
}

static PyObject *
add_custom_num_format(XLPyBook *self, PyObject *args)
{
	const char *fmt;
	if(!PyArg_ParseTuple(args, "s", &fmt)) return NULL;

	int index = xlBookAddCustomNumFormat(self->handler, fmt);
	if(!index) Py_RETURN_NONE;
	return Py_BuildValue("i", index);
}

static PyObject *
custom_num_format(XLPyBook *self, PyObject *args)
{
	const int fmt;
	if(!PyArg_ParseTuple(args, "i", &fmt)) return NULL;

	return Py_BuildValue("s",
			xlBookCustomNumFormat(self->handler, fmt));
}

static PyObject *
format(XLPyBook *self, PyObject *args)
{
	int num;
	if(!PyArg_ParseTuple(args, "i", &num)) return NULL;
	FormatHandle format = xlBookFormat(self->handler, num);
	if(!format) Py_RETURN_NONE;

	XLPyFormat *obj = PyObject_New(XLPyFormat, &XLPyFormatType);
	obj->handler = format;
	return (PyObject *)obj;
}

static PyObject *
format_size(XLPyBook *self)
{
	return Py_BuildValue("i",
			xlBookFormatSize(self->handler));
}

static PyObject *
font(XLPyBook *self, PyObject *args)
{
	const int index;
	if(!PyArg_ParseTuple(args, "i", &index)) return NULL;

	FontHandle font = xlBookFont(self->handler, index);
	if(!font) Py_RETURN_NONE;

	XLPyFont *obj = PyObject_New(XLPyFont, &XLPyFontType);
	obj->handler = font;
	return (PyObject *)obj;
}

static PyObject *
font_size(XLPyBook *self)
{
	return Py_BuildValue("i", xlBookFontSize(self->handler));
}

static PyObject *
date_pack(XLPyBook *self, PyObject *args)
{
    int year, month, day, hour, min, sec, msec;
    if(!PyArg_ParseTuple(args, "iiiiiii",
                &year, &month, &day, &hour, &min, &sec, &msec)) {
        return NULL;
    }

    double pack = xlBookDatePack(self->handler,
            year, month, day, hour, min, sec, msec);
    return Py_BuildValue("d", pack);
}

static PyObject *
date_unpack(XLPyBook *self, PyObject *args)
{
    double pack;
    if(!PyArg_ParseTuple(args, "d", &pack)) return NULL;

    int year, month, day, hour, min, sec, msec;
    if(0 == xlBookDateUnpack(self->handler, pack,
            &year, &month, &day, &hour, &min, &sec, &msec)) {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("(iiiiiii)",
            year, month, day, hour, min, sec, msec);
}

static PyObject *
color_pack(XLPyBook *self, PyObject *args)
{
    int r, g, b;
    if(!PyArg_ParseTuple(args, "iii", &r, &g, &b)) return NULL;
    return Py_BuildValue("i", xlBookColorPack(self->handler, r, g, b));
}

static PyObject *
color_unpack(XLPyBook *self, PyObject *args)
{
    int color;
    if(!PyArg_ParseTuple(args, "i", &color)) return NULL;

    int r, g, b;
    xlBookColorUnpack(self->handler, color, &r, &g, &b);
    return Py_BuildValue("(iii)", r, g, b);
}

static PyObject *
ref_r1_c1(XLPyBook *self)
{
    if(xlBookRefR1C1(self->handler))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
set_ref_r1_c1(XLPyBook *self, PyObject *args)
{
    PyObject *val = NULL;
    if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &val)) return NULL;
    xlBookSetRefR1C1(self->handler, PyObject_IsTrue(val) ? 1 : 0);
    Py_RETURN_NONE;
}

static PyObject *
rgb_mode(XLPyBook *self)
{
    if(xlBookRgbMode(self->handler))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
set_rgb_mode(XLPyBook *self, PyObject *args)
{
    PyObject *val = NULL;
    if(!PyArg_ParseTuple(args, "O!", &PyBool_Type, &val)) return NULL;
    xlBookSetRgbMode(self->handler, PyObject_IsTrue(val) ? 1 : 0);
    Py_RETURN_NONE;
}

static PyObject *
biff_version(XLPyBook *self)
{
    return Py_BuildValue("i", xlBookBiffVersion(self->handler));
}

/*
static PyObject *
is_date_1904(XLPyBook *self)
{
    if(xlBookIsDate1904(self->handler))
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
set_date_1904(XLPyBook *self, PyObject *args)
{
    int value;
    if(!PyArg_ParseTuple(args, "i", &value)) return NULL;
    xlBookIsDate1904(self->handler, value);
    Py_RETURN_NONE;
}
*/

static PyObject *
set_key(XLPyBook *self, PyObject *args)
{
	const char *name, *key;
	if(!PyArg_ParseTuple(args, "ss", &name, &key)) return NULL;

	xlBookSetKey(self->handler, name, key);
	Py_RETURN_NONE;
}

static PyObject *
set_locale(XLPyBook *self, PyObject *args)
{
	const char *locale;
	if(!PyArg_ParseTuple(args, "s", &locale)) return NULL;

	if (xlBookSetLocale(self->handler, locale))
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
error_message(XLPyBook *self)
{
	return Py_BuildValue("s", xlBookErrorMessage(self->handler));
}

static PyMethodDef methods[] = {
	{"load", (PyCFunction) load, METH_VARARGS,
		"When second arg is True, it loads a xls-file from buffer."
		"When is not present or False, it loads xls-file from file path."
		"Returns False if error occurs."},
	{"save", (PyCFunction) save, METH_VARARGS,
		"When arg is a string, saves current workbook into xls-file."
		"When no args, returns xls-file as a buffer."
		"Returns False if error occurs"},
	{"addSheet", (PyCFunction) add_sheet, METH_VARARGS,
		"Adds a new sheet to this book, returns the sheet object. "
		"Use initSheet parameter if you wish to copy an existing sheet. "
		"Note initSheet must be only from this book. Returns None if error occurs."},
	{"getSheet", (PyCFunction) get_sheet, METH_VARARGS,
		"Gets pointer to a sheet with specified index. "
		"Returns None if error occurs."},
	{"sheetType", (PyCFunction) sheet_type, METH_VARARGS,
		"Returns type of sheet with specified index."},
	{"delSheet", (PyCFunction) del_sheet, METH_VARARGS,
		"Deletes a sheet with specified index. Returns false if error occurs. "},
	{"sheetCount", (PyCFunction) sheet_count, METH_VARARGS,
		"Returns a number of sheets in this book."},
	{"addFormat", (PyCFunction) add_format, METH_VARARGS,
		"Adds a new format to the workbook, initial parameters can be copied from other format. "
		"Returns None if error occurs."},
	{"addFont", (PyCFunction) add_font, METH_VARARGS,
		"Adds a new font to the workbook, initial parameters can be copied from other font. "
		"Returns None if error occurs."},
	{"addCustomNumFormat", (PyCFunction) add_custom_num_format, METH_VARARGS,
		"Adds a new custom number format to the workbook. "
		"The format string customNumFormat indicates how to format and render the numeric value of a cell. "
		"See custom format strings guidelines. "
		"Returns the custom format identifier. "
		"It's used in Book::formatSetNumFormat(). "
		"Returns None if error occurs."},
	{"customNumFormat", (PyCFunction) custom_num_format, METH_VARARGS,
		"Returns a custom format string for specified custom format identifier fmt. "
		"See custom format string guidelines."},
	{"format", (PyCFunction) format, METH_VARARGS,
		"Returns a format with defined index. "
		"Index must be less than return value of formatSize() method."},
	{"formatSize", (PyCFunction) format_size, METH_NOARGS,
		"Returns a number of formats in this book."},
	{"font", (PyCFunction) font, METH_VARARGS,
		"Returns a font with defined index. "
		"Index must be less than return value of Book::fontSize() method."},
	{"fontSize", (PyCFunction) font_size, METH_NOARGS,
		"Returns a number of fonts in this book."},
    {"datePack", (PyCFunction) date_pack, METH_VARARGS,
        "Packs date and time information into float type."},
    {"dateUnpack", (PyCFunction) date_unpack, METH_VARARGS,
        "Unpacks date and time information from float type. Returns None if error occurs."},
    {"colorPack", (PyCFunction) color_pack, METH_VARARGS,
        "Packs red, green and blue components in color value."},
    {"colorUnpack", (PyCFunction) color_unpack, METH_VARARGS,
        "Unpacks color value to red, green and blue components."},
	{"activeSheet", (PyCFunction) active_sheet, METH_NOARGS,
		"Returns an active sheet index in this workbook."},
	{"setActiveSheet", (PyCFunction) set_active_sheet, METH_VARARGS,
		"Sets an active sheet index in this workbook."},
	{"pictureSize", (PyCFunction) picture_size, METH_NOARGS,
		"Returns a number of pictures in this workbook."},
	{"getPicture", (PyCFunction) get_picture, METH_VARARGS,
		"Returns a tuple with type of picture and picture buffer"},
	{"addPicture", (PyCFunction) add_picture, METH_VARARGS,
		"Adds a picture to the workbook. Returns a picture identifier. "
		"Supports BMP, DIB, PNG, JPG and WMF picture formats. "
		"Use picture identifier with Sheet::SetPicture(). "
		"Returns -1 if error occurs. "},
	{"addPicture2", (PyCFunction) add_picture2, METH_VARARGS,
		"Adds a picture to the workbook from memory buffer: \n"
		"data - pointer to buffer with picture data (BMP, DIB, PNG, JPG or WMF formats);"
		"Returns a picture identifier. Use picture identifier with Book::sheetSetPicture()"},
    {"defaultFont", (PyCFunction) default_font, METH_NOARGS,
        "Returns a tuple with default font name and size for this workbook. "
        "Returns None if error occurs."},
    {"setDefaultFont", (PyCFunction) set_default_font, METH_VARARGS,
        "Sets a default font name and size for this workbook."},
	{"refR1C1", (PyCFunction) ref_r1_c1, METH_VARARGS,
		"Returns whether the R1C1 reference mode is active. "
		"Returns True if mode is active and False if isn't."},
	{"setRefR1C1", (PyCFunction) set_ref_r1_c1, METH_VARARGS,
		"Sets the R1C1 reference mode: True - active, False - not active."},
    {"rgbMode", (PyCFunction) rgb_mode, METH_NOARGS,
        "Returns whether the RGB mode is active: "
        "True - RGB mode, False - Index mode."},
    {"setRgbMode", (PyCFunction) set_rgb_mode, METH_VARARGS,
        "Sets a RGB mode: True - RGB mode, False - Index mode (default). "
        "In RGB mode use Book::ColorPack() and Book::ColorUnpack() functions for getting/setting colors."},
    {"biffVersion", (PyCFunction) biff_version, METH_NOARGS,
        "Returns BIFF version of binary file. Used for xls format only."},
    /*
    {"isDate1904", (PyCFunction) is_date_1904, METH_NOARGS,
        "Returns whether the 1904 date system is active: "
        "True - 1904 date system, False - 1900 date system."},
    {"setDate1904", (PyCFunction) set_date_1904, METH_NOARGS,
        "Sets the date system mode: True - 1904 date system, False - 1900 date system (default). "
        "In the 1900 date base system, the lower limit is January 1, 1900, which has serial value 1. "
        "In the 1904 date base system, the lower limit is January 1, 1904, which has serial value 0."},
    */
	{"setKey", (PyCFunction) set_key, METH_VARARGS,
		"Sets customer's license key."},
	{"setLocale", (PyCFunction) set_locale, METH_VARARGS,
		"Sets the locale for this library. "
		"The locale argument is the same as the locale argument in setlocale() function from C Run-Time Library. "
		"For example, value \"en_US.UTF-8\" allows to use non-ascii characters in Linux or Mac. "
        "It accepts the special value \"UTF-8\" for using UTF-8 character encoding in Windows and other operating systems. "
		"It has no effect for unicode projects with wide strings (with _UNICODE preprocessor variable). "
		"Returns True if a valid locale argument is given."},
	{"errorMessage", (PyCFunction) error_message, METH_NOARGS,
		"Returns the last error message."},
	{NULL}
};

PyTypeObject
XLPyBookType = {
   PyObject_HEAD_INIT(NULL)
   0,                         /* ob_size */
   "XLPyBook",                /* tp_name */
   sizeof(XLPyBook),          /* tp_basicsize */
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
   "XLPy Book",                 /* tp_doc */
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
