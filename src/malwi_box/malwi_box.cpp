#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stdlib.h>

// Py_IsFinalizing was added in Python 3.13, use private API for older versions
#if PY_VERSION_HEX < 0x030D0000
#define Py_IsFinalizing() _Py_IsFinalizing()
#endif

// Module state structure
typedef struct {
    PyObject *callback;  // User-provided Python callable
    PyObject *blocklist; // Set of event names to block
    int hook_registered; // Whether the audit hook has been registered
    int profile_registered; // Whether the profile hook has been registered
} AuditHookState;

// Get module state
static AuditHookState* get_state(PyObject *module) {
    return (AuditHookState*)PyModule_GetState(module);
}

// Global pointer to module for use in audit hook callback
static PyObject *g_module = NULL;

// Cached references for env var monitoring
static PyObject *g_os_module = NULL;
static PyObject *g_os_getenv = NULL;
static PyObject *g_os_environ = NULL;

// Check if a string matches (for quick C-level checks)
static inline int streq(const char *a, const char *b) {
    return strcmp(a, b) == 0;
}

// Events that are blocked at the C level for security
static inline int is_blocked_event(const char *event) {
    return streq(event, "sys.addaudithook") ||
           streq(event, "sys.setprofile") ||
           streq(event, "sys.settrace");
}

// The C audit hook function registered with PySys_AddAuditHook
static int audit_hook(const char *event, PyObject *args, void *userData) {
    // Block dangerous events that could bypass security
    // We terminate immediately because returning -1 causes issues with some events
    if (is_blocked_event(event)) {
        PySys_WriteStderr("[malwi-box] BLOCKED: %s - Terminating for security\n", event);
        fflush(stderr);
        _exit(77);  // Use _exit to terminate immediately without cleanup
    }

    // Skip if interpreter is finalizing to avoid accessing freed objects
    if (Py_IsFinalizing()) {
        return 0;
    }

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

    // Check if event is in blocklist
    if (state->blocklist != NULL) {
        int contains = PySet_Contains(state->blocklist, event_str);
        if (contains == 1) {
            Py_DECREF(event_str);
            return 0;  // Skip blocked event
        }
        // contains == -1 means error, but we'll continue anyway
    }

    // Call the Python callback with (event, args)
    PyObject *result = PyObject_CallFunctionObjArgs(
        state->callback, event_str, args, NULL
    );

    Py_DECREF(event_str);

    if (result == NULL) {
        // Exception occurred in callback
        if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
            // For SystemExit, extract the exit code and terminate immediately
            PyObject *exc_type, *exc_value, *exc_tb;
            PyErr_Fetch(&exc_type, &exc_value, &exc_tb);

            int exit_code = 1;
            if (exc_value != NULL) {
                PyObject *code = PyObject_GetAttrString(exc_value, "code");
                if (code != NULL && PyLong_Check(code)) {
                    exit_code = (int)PyLong_AsLong(code);
                }
                Py_XDECREF(code);
            }

            Py_XDECREF(exc_type);
            Py_XDECREF(exc_value);
            Py_XDECREF(exc_tb);

            _exit(exit_code);
        }
        if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
            PyErr_Clear();
            _exit(130);
        }
        // For other exceptions, print and continue
        PyErr_Print();
        PyErr_Clear();
        return 0;
    }

    Py_DECREF(result);
    return 0;
}

// Helper to invoke the audit callback with a custom event
static void invoke_audit_callback(const char *event, PyObject *args_tuple) {
    if (g_module == NULL) {
        return;
    }

    AuditHookState *state = get_state(g_module);
    if (state == NULL || state->callback == NULL) {
        return;
    }

    PyObject *event_str = PyUnicode_FromString(event);
    if (event_str == NULL) {
        return;
    }

    // Check if event is in blocklist
    if (state->blocklist != NULL) {
        int contains = PySet_Contains(state->blocklist, event_str);
        if (contains == 1) {
            Py_DECREF(event_str);
            return;
        }
    }

    PyObject *result = PyObject_CallFunctionObjArgs(
        state->callback, event_str, args_tuple, NULL
    );

    Py_DECREF(event_str);

    if (result == NULL) {
        if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
            PyObject *exc_type, *exc_value, *exc_tb;
            PyErr_Fetch(&exc_type, &exc_value, &exc_tb);
            int exit_code = 78;
            if (exc_value != NULL) {
                PyObject *code = PyObject_GetAttrString(exc_value, "code");
                if (code != NULL && PyLong_Check(code)) {
                    exit_code = (int)PyLong_AsLong(code);
                }
                Py_XDECREF(code);
            }
            Py_XDECREF(exc_type);
            Py_XDECREF(exc_value);
            Py_XDECREF(exc_tb);
            _exit(exit_code);
        }
        if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
            PyErr_Clear();
            _exit(130);
        }
        PyErr_Print();
        PyErr_Clear();
    } else {
        Py_DECREF(result);
    }
}

// Profile hook function for monitoring env var access
static int profile_hook(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) {
    // Only interested in C function calls
    if (what != PyTrace_C_CALL) {
        return 0;
    }

    // Skip if finalizing
    if (Py_IsFinalizing()) {
        return 0;
    }

    if (g_module == NULL) {
        return 0;
    }

    AuditHookState *state = get_state(g_module);
    if (state == NULL || !state->profile_registered) {
        return 0;
    }

    // arg is the function being called
    if (arg == NULL || !PyCFunction_Check(arg)) {
        return 0;
    }

    // Get function name
    const char *func_name = ((PyCFunctionObject *)arg)->m_ml->ml_name;
    if (func_name == NULL) {
        return 0;
    }

    // Check if this is os.getenv or os.environ.get
    int is_getenv = streq(func_name, "getenv");
    int is_environ_get = streq(func_name, "get");

    if (!is_getenv && !is_environ_get) {
        return 0;
    }

    // For os.environ.get, verify it's from os.environ
    if (is_environ_get) {
        PyObject *self_obj = ((PyCFunctionObject *)arg)->m_self;
        if (self_obj == NULL || self_obj != g_os_environ) {
            return 0;
        }
    }

    // Create a custom audit event "os.getenv" or "os.environ.get"
    // We pass the function object as args so the callback can inspect it
    const char *event_name = is_getenv ? "os.getenv" : "os.environ.get";

    PyObject *args_tuple = PyTuple_New(1);
    if (args_tuple == NULL) {
        return 0;
    }
    Py_INCREF(arg);
    PyTuple_SET_ITEM(args_tuple, 0, arg);

    invoke_audit_callback(event_name, args_tuple);

    Py_DECREF(args_tuple);
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

        // Register the profile hook for env var monitoring BEFORE the audit hook
        // (because audit hook blocks sys.setprofile events)
        // Cache os module references first
        if (g_os_module == NULL) {
            g_os_module = PyImport_ImportModule("os");
            if (g_os_module != NULL) {
                g_os_getenv = PyObject_GetAttrString(g_os_module, "getenv");
                g_os_environ = PyObject_GetAttrString(g_os_module, "environ");
            }
        }
        PyEval_SetProfile(profile_hook, NULL);
        state->profile_registered = 1;

        // Now register the audit hook
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

// Python-callable function to set the blocklist
static PyObject* set_blocklist(PyObject *self, PyObject *args) {
    PyObject *blocklist;

    if (!PyArg_ParseTuple(args, "O", &blocklist)) {
        return NULL;
    }

    // Accept None to clear, or a set/frozenset/list of strings
    if (blocklist == Py_None) {
        AuditHookState *state = get_state(self);
        if (state == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "module state not available");
            return NULL;
        }
        Py_XDECREF(state->blocklist);
        state->blocklist = NULL;
        Py_RETURN_NONE;
    }

    // Convert to a set if not already
    PyObject *blocklist_set;
    if (PySet_Check(blocklist) || PyFrozenSet_Check(blocklist)) {
        blocklist_set = PySet_New(blocklist);
    } else if (PyList_Check(blocklist) || PyTuple_Check(blocklist)) {
        blocklist_set = PySet_New(blocklist);
    } else {
        PyErr_SetString(PyExc_TypeError, "blocklist must be a set, list, tuple, or None");
        return NULL;
    }

    if (blocklist_set == NULL) {
        return NULL;
    }

    AuditHookState *state = get_state(self);
    if (state == NULL) {
        Py_DECREF(blocklist_set);
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }

    Py_XDECREF(state->blocklist);
    state->blocklist = blocklist_set;

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
    {"set_blocklist", set_blocklist, METH_VARARGS,
     "Set a blocklist of event names to skip.\n\n"
     "Args:\n"
     "    blocklist: A set, list, or tuple of event names to block, or None to clear\n"},
    {NULL, NULL, 0, NULL}
};

// Module traversal for GC
static int module_traverse(PyObject *module, visitproc visit, void *arg) {
    AuditHookState *state = get_state(module);
    if (state != NULL) {
        Py_VISIT(state->callback);
        Py_VISIT(state->blocklist);
    }
    return 0;
}

// Module clear for GC
static int module_clear(PyObject *module) {
    // Clear global module pointer to prevent audit hook from accessing freed memory
    if (g_module == module) {
        Py_CLEAR(g_module);
    }

    // Clear cached os module references
    Py_CLEAR(g_os_module);
    Py_CLEAR(g_os_getenv);
    Py_CLEAR(g_os_environ);

    AuditHookState *state = get_state(module);
    if (state != NULL) {
        Py_CLEAR(state->callback);
        Py_CLEAR(state->blocklist);
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
    state->blocklist = NULL;
    state->hook_registered = 0;
    state->profile_registered = 0;

    return module;
}
