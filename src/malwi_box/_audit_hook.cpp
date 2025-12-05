#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Module state structure
typedef struct {
    PyObject *callback;  // User-provided Python callable
    int hook_registered; // Whether the audit hook has been registered
} AuditHookState;

// Get module state
static AuditHookState* get_state(PyObject *module) {
    return (AuditHookState*)PyModule_GetState(module);
}

// Global pointer to module for use in audit hook callback
static PyObject *g_module = NULL;

// The C audit hook function registered with PySys_AddAuditHook
static int audit_hook(const char *event, PyObject *args, void *userData) {
    // Get the module from global pointer
    if (g_module == NULL) {
        return 0;
    }

    AuditHookState *state = get_state(g_module);
    if (state == NULL || state->callback == NULL) {
        return 0;
    }

    // GIL should already be held when audit hook is called
    PyObject *event_str = PyUnicode_FromString(event);
    if (event_str == NULL) {
        return 0;  // Don't abort on encoding errors
    }

    // Call the Python callback with (event, args)
    PyObject *result = PyObject_CallFunctionObjArgs(
        state->callback, event_str, args, NULL
    );

    Py_DECREF(event_str);

    if (result == NULL) {
        // Exception occurred in callback
        // Check if it's a SystemExit or similar that should abort
        if (PyErr_ExceptionMatches(PyExc_SystemExit) ||
            PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
            return -1;  // Abort the operation
        }
        // For other exceptions, print and continue
        PyErr_Print();
        PyErr_Clear();
        return 0;
    }

    Py_DECREF(result);
    return 0;
}

// Python-callable function to set the callback
static PyObject* set_callback(PyObject *self, PyObject *args) {
    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O", &callback)) {
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    AuditHookState *state = get_state(self);
    if (state == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }

    // Store new callback (replacing old one if any)
    Py_XDECREF(state->callback);
    Py_INCREF(callback);
    state->callback = callback;

    // Register the audit hook if not already done
    if (!state->hook_registered) {
        // Store global module reference for audit hook
        g_module = self;
        Py_INCREF(g_module);

        if (PySys_AddAuditHook(audit_hook, NULL) < 0) {
            PyErr_SetString(PyExc_RuntimeError, "failed to add audit hook");
            return NULL;
        }
        state->hook_registered = 1;
    }

    Py_RETURN_NONE;
}

// Python-callable function to clear the callback
static PyObject* clear_callback(PyObject *self, PyObject *args) {
    AuditHookState *state = get_state(self);
    if (state == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }

    Py_XDECREF(state->callback);
    state->callback = NULL;

    Py_RETURN_NONE;
}

// Module methods
static PyMethodDef module_methods[] = {
    {"set_callback", set_callback, METH_VARARGS,
     "Set the audit hook callback function.\n\n"
     "Args:\n"
     "    callback: A callable that takes (event: str, args: tuple)\n"},
    {"clear_callback", clear_callback, METH_NOARGS,
     "Clear the audit hook callback (hook remains registered but inactive)."},
    {NULL, NULL, 0, NULL}
};

// Module traversal for GC
static int module_traverse(PyObject *module, visitproc visit, void *arg) {
    AuditHookState *state = get_state(module);
    if (state != NULL) {
        Py_VISIT(state->callback);
    }
    return 0;
}

// Module clear for GC
static int module_clear(PyObject *module) {
    AuditHookState *state = get_state(module);
    if (state != NULL) {
        Py_CLEAR(state->callback);
    }
    return 0;
}

// Module deallocation
static void module_free(void *module) {
    module_clear((PyObject*)module);
}

// Module definition
static struct PyModuleDef audit_hook_module = {
    PyModuleDef_HEAD_INIT,
    "_audit_hook",
    "C++ extension for Python audit hooks",
    sizeof(AuditHookState),
    module_methods,
    NULL,
    module_traverse,
    module_clear,
    module_free
};

// Module initialization
PyMODINIT_FUNC PyInit__audit_hook(void) {
    PyObject *module = PyModule_Create(&audit_hook_module);
    if (module == NULL) {
        return NULL;
    }

    AuditHookState *state = get_state(module);
    if (state == NULL) {
        Py_DECREF(module);
        return NULL;
    }

    state->callback = NULL;
    state->hook_registered = 0;

    return module;
}
