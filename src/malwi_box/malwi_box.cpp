#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <stdlib.h>

// For Python 3.10, we need access to frame internals
#if PY_VERSION_HEX < 0x030B0000
#include <frameobject.h>
#endif

// Py_IsFinalizing was added in Python 3.13, use private API for older versions
#if PY_VERSION_HEX < 0x030D0000
#define Py_IsFinalizing() _Py_IsFinalizing()
#endif

// PyFrame_GetLocals was added in Python 3.11
// In Python 3.10, we need to call PyFrame_FastToLocals first to populate f_locals
#if PY_VERSION_HEX < 0x030B0000
static inline PyObject* PyFrame_GetLocals(PyFrameObject *frame) {
    // Force population of f_locals from fast locals
    PyFrame_FastToLocals(frame);
    PyObject *locals = frame->f_locals;
    Py_XINCREF(locals);
    return locals;
}
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

// Helper to get item from locals (works with both dict and frame-locals proxy in Python 3.13+)
static PyObject* get_local_item(PyObject *locals, const char *key) {
    PyObject *result = NULL;
    // First try dict access (fast path for Python < 3.13)
    if (PyDict_Check(locals)) {
        result = PyDict_GetItemString(locals, key);
        if (result != NULL) {
            Py_INCREF(result);  // PyDict_GetItemString returns borrowed ref
        }
    } else {
        // Use mapping protocol for frame-locals proxy (Python 3.13+)
        PyObject *key_obj = PyUnicode_FromString(key);
        if (key_obj != NULL) {
            result = PyObject_GetItem(locals, key_obj);
            Py_DECREF(key_obj);
            if (result == NULL) {
                PyErr_Clear();  // KeyError is expected
            }
        }
    }
    return result;  // Returns new reference or NULL
}

// Extract URL and method from frame locals and report http.request event
static void extract_and_report_http_request(PyFrameObject *frame) {
    PyObject *locals = PyFrame_GetLocals(frame);
    if (locals == NULL) return;

    PyObject *url = NULL;
    PyObject *method = NULL;

    // Try common parameter names for URL
    url = get_local_item(locals, "url");
    if (url == NULL) url = get_local_item(locals, "fullurl");
    if (url == NULL) url = get_local_item(locals, "str_or_url");  // aiohttp

    // Try common parameter names for method
    method = get_local_item(locals, "method");

    // Convert URL object to string if needed (httpx uses URL objects)
    PyObject *url_str = NULL;
    if (url != NULL) {
        if (PyUnicode_Check(url)) {
            url_str = url;
            Py_INCREF(url_str);
        } else {
            // Try str(url) for URL objects
            url_str = PyObject_Str(url);
        }
    }

    if (url_str != NULL) {
        PyObject *method_str = NULL;
        if (method == NULL) {
            method_str = PyUnicode_FromString("GET");
        } else if (PyUnicode_Check(method)) {
            method_str = method;
            Py_INCREF(method_str);
        } else {
            method_str = PyObject_Str(method);
        }

        if (method_str != NULL) {
            PyObject *args = PyTuple_Pack(2, url_str, method_str);
            if (args != NULL) {
                invoke_audit_callback("http.request", args);
                Py_DECREF(args);
            }
            Py_DECREF(method_str);
        }

        Py_DECREF(url_str);
    }

    // Cleanup - get_local_item returns new references
    Py_XDECREF(url);
    Py_XDECREF(method);
    Py_DECREF(locals);
}

// Extract URL from http.client HTTPConnection.request
// The URL parameter only contains the path, host/port are on self
static void extract_http_client_request(PyFrameObject *frame) {
    PyObject *locals = PyFrame_GetLocals(frame);
    if (locals == NULL) return;

    PyObject *self_obj = get_local_item(locals, "self");
    PyObject *method = get_local_item(locals, "method");
    PyObject *path = get_local_item(locals, "url");

    if (self_obj == NULL) {
        Py_XDECREF(method);
        Py_XDECREF(path);
        Py_DECREF(locals);
        return;
    }

    // Get host and port from self
    PyObject *host = PyObject_GetAttrString(self_obj, "host");
    PyObject *port = PyObject_GetAttrString(self_obj, "port");

    if (host == NULL) {
        Py_XDECREF(port);
        Py_XDECREF(self_obj);
        Py_XDECREF(method);
        Py_XDECREF(path);
        Py_DECREF(locals);
        return;
    }

    // Determine scheme by checking class name for HTTPS
    const char *scheme = "http";
    PyObject *cls = PyObject_GetAttrString(self_obj, "__class__");
    if (cls != NULL) {
        PyObject *cls_name = PyObject_GetAttrString(cls, "__name__");
        if (cls_name != NULL && PyUnicode_Check(cls_name)) {
            const char *name = PyUnicode_AsUTF8(cls_name);
            if (name != NULL && strstr(name, "HTTPS") != NULL) {
                scheme = "https";
            }
        }
        Py_XDECREF(cls_name);
        Py_DECREF(cls);
    }

    // Build full URL: scheme://host:port/path
    const char *host_str = PyUnicode_Check(host) ? PyUnicode_AsUTF8(host) : "";
    const char *path_str = (path != NULL && PyUnicode_Check(path)) ? PyUnicode_AsUTF8(path) : "/";
    long port_num = (port != NULL && PyLong_Check(port)) ? PyLong_AsLong(port) : 0;

    char url_buf[2048];
    if (port_num > 0 && port_num != 80 && port_num != 443) {
        snprintf(url_buf, sizeof(url_buf), "%s://%s:%ld%s", scheme, host_str, port_num, path_str);
    } else {
        snprintf(url_buf, sizeof(url_buf), "%s://%s%s", scheme, host_str, path_str);
    }

    PyObject *url_str = PyUnicode_FromString(url_buf);
    if (url_str != NULL) {
        PyObject *method_str = NULL;
        if (method == NULL) {
            method_str = PyUnicode_FromString("GET");
        } else if (PyUnicode_Check(method)) {
            method_str = method;
            Py_INCREF(method_str);
        } else {
            method_str = PyObject_Str(method);
        }

        if (method_str != NULL) {
            PyObject *args = PyTuple_Pack(2, url_str, method_str);
            if (args != NULL) {
                invoke_audit_callback("http.request", args);
                Py_DECREF(args);
            }
            Py_DECREF(method_str);
        }
        Py_DECREF(url_str);
    }

    Py_DECREF(host);
    Py_XDECREF(port);
    Py_DECREF(self_obj);
    Py_XDECREF(method);
    Py_XDECREF(path);
    Py_DECREF(locals);
}

// Check if current frame is an HTTP request function
static void check_http_function_call(PyFrameObject *frame) {
    PyCodeObject *code = PyFrame_GetCode(frame);
    if (code == NULL) return;

    PyObject *name_obj = code->co_name;
    PyObject *filename_obj = code->co_filename;

    if (name_obj == NULL || filename_obj == NULL) {
        Py_DECREF(code);
        return;
    }

    const char *func_name = PyUnicode_AsUTF8(name_obj);
    const char *filename = PyUnicode_AsUTF8(filename_obj);

    if (func_name == NULL || filename == NULL) {
        Py_DECREF(code);
        return;
    }

    // Quick check: only interested in "urlopen" or "request" functions
    int is_http_func = 0;

    if (streq(func_name, "urlopen")) {
        // urllib.request.urlopen or urllib3 HTTPConnectionPool.urlopen
        if (strstr(filename, "urllib/request.py") != NULL ||
            strstr(filename, "urllib3/connectionpool.py") != NULL) {
            is_http_func = 1;
        }
    } else if (streq(func_name, "request")) {
        // requests Session.request, httpx Client.request, or http.client HTTPConnection.request
        if (strstr(filename, "requests/sessions.py") != NULL ||
            strstr(filename, "httpx/_client.py") != NULL ||
            strstr(filename, "http/client.py") != NULL) {
            is_http_func = 1;
        }
    } else if (streq(func_name, "_request")) {
        // aiohttp ClientSession._request
        if (strstr(filename, "aiohttp/client.py") != NULL) {
            is_http_func = 1;
        }
    }

    int is_http_client = 0;
    if (is_http_func && strstr(filename, "http/client.py") != NULL) {
        is_http_client = 1;
    }

    if (is_http_func) {
        if (is_http_client) {
            extract_http_client_request(frame);
        } else {
            extract_and_report_http_request(frame);
        }
    }

    Py_DECREF(code);
}

// Profile hook function for monitoring env var access and HTTP requests
static int profile_hook(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) {
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

    // Handle Python function calls (PyTrace_CALL) for HTTP interception
    if (what == PyTrace_CALL) {
        check_http_function_call(frame);
        return 0;
    }

    // Handle C function calls (PyTrace_C_CALL) for env var monitoring
    if (what != PyTrace_C_CALL) {
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
