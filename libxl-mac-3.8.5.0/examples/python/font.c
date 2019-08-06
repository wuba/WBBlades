#include <Python.h>
#include <libxl.h>

#include "font.h"

static int
init(XLPyFont *self)
{
    return 0;
}

static void
dealloc(XLPyFont *self)
{
	self->ob_type->tp_free((PyObject*)self);
}

static PyMethodDef methods[] = {
	{NULL}
};

PyTypeObject XLPyFontType = {
   PyObject_HEAD_INIT(NULL)
   0,                         /* ob_size */
   "XLPyFont",              /* tp_name */
   sizeof(XLPyFont),          /* tp_basicsize */
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
   "XLPy Font"  ,             /* tp_doc */
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
