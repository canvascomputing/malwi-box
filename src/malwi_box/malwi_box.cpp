// =============================================================================
// Section 1: Includes and Version Compatibility
// =============================================================================

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

// =============================================================================
// Section 2: Module State and Globals
// =============================================================================

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
static PyObject *g_os_getenv_original = NULL;
static PyObject *g_os_environ_original = NULL;

// Re-entrancy guard for env var events (prevents double-firing when os.getenv calls os.environ.get)
static int g_in_env_callback = 0;

// =============================================================================
// Section 3: AuditedEnviron Type - C wrapper for os.environ
// =============================================================================

typedef struct {
    PyObject_HEAD
    PyObject *wrapped;  // Original os.environ
} AuditedEnvironObject;

// Helper to invoke audit callback (forward declaration, defined below)
static void invoke_audit_callback(const char *event, PyObject *args_tuple);

// AuditedEnviron.__getitem__(key) - fires audit event on environ[key]
static PyObject *AuditedEnviron_subscript(AuditedEnvironObject *self, PyObject *key) {
    // Fire audit event with the key (unless already in an env callback)
    if (!g_in_env_callback) {
        g_in_env_callback = 1;
        PyObject *args = PyTuple_Pack(1, key);
        if (args != NULL) {
            invoke_audit_callback("os.environ.get", args);
            Py_DECREF(args);
        }
        g_in_env_callback = 0;
    }
    // Delegate to wrapped environ
    return PyObject_GetItem(self->wrapped, key);
}

// AuditedEnviron.__setitem__(key, value)
static int AuditedEnviron_ass_subscript(AuditedEnvironObject *self, PyObject *key, PyObject *value) {
    if (value == NULL) {
        // Deletion: environ.__delitem__(key)
        return PyObject_DelItem(self->wrapped, key);
    }
    // Set: environ.__setitem__(key, value)
    return PyObject_SetItem(self->wrapped, key, value);
}

// AuditedEnviron.__len__()
static Py_ssize_t AuditedEnviron_length(AuditedEnvironObject *self) {
    return PyObject_Size(self->wrapped);
}

// Mapping methods for subscript access
static PyMappingMethods AuditedEnviron_as_mapping = {
    (lenfunc)AuditedEnviron_length,           // mp_length
    (binaryfunc)AuditedEnviron_subscript,     // mp_subscript (__getitem__)
    (objobjargproc)AuditedEnviron_ass_subscript,  // mp_ass_subscript (__setitem__/__delitem__)
};

// AuditedEnviron.get(key, default=None) - fires audit event
static PyObject *AuditedEnviron_get(AuditedEnvironObject *self, PyObject *args) {
    PyObject *key, *default_val = Py_None;
    if (!PyArg_ParseTuple(args, "O|O", &key, &default_val)) {
        return NULL;
    }

    // Fire audit event (unless already in an env callback)
    if (!g_in_env_callback) {
        g_in_env_callback = 1;
        PyObject *event_args = PyTuple_Pack(1, key);
        if (event_args != NULL) {
            invoke_audit_callback("os.environ.get", event_args);
            Py_DECREF(event_args);
        }
        g_in_env_callback = 0;
    }

    // Delegate to wrapped environ.get()
    return PyObject_CallMethod(self->wrapped, "get", "OO", key, default_val);
}

// AuditedEnviron.__contains__(key) - for "key in environ"
static int AuditedEnviron_contains(AuditedEnvironObject *self, PyObject *key) {
    return PySequence_Contains(self->wrapped, key);
}

// Sequence methods for __contains__
static PySequenceMethods AuditedEnviron_as_sequence = {
    0,                                        // sq_length
    0,                                        // sq_concat
    0,                                        // sq_repeat
    0,                                        // sq_item
    0,                                        // sq_slice
    0,                                        // sq_ass_item
    0,                                        // sq_ass_slice
    (objobjproc)AuditedEnviron_contains,     // sq_contains
    0,                                        // sq_inplace_concat
    0,                                        // sq_inplace_repeat
};

// Forward method calls to the wrapped environ for methods we don't intercept
static PyObject *AuditedEnviron_keys(AuditedEnvironObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyObject_CallMethod(self->wrapped, "keys", NULL);
}

static PyObject *AuditedEnviron_values(AuditedEnvironObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyObject_CallMethod(self->wrapped, "values", NULL);
}

static PyObject *AuditedEnviron_items(AuditedEnvironObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyObject_CallMethod(self->wrapped, "items", NULL);
}

static PyObject *AuditedEnviron_copy(AuditedEnvironObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyObject_CallMethod(self->wrapped, "copy", NULL);
}

static PyObject *AuditedEnviron_pop(AuditedEnvironObject *self, PyObject *args) {
    PyObject *method = PyObject_GetAttrString(self->wrapped, "pop");
    if (method == NULL) return NULL;
    PyObject *result = PyObject_Call(method, args, NULL);
    Py_DECREF(method);
    return result;
}

static PyObject *AuditedEnviron_setdefault(AuditedEnvironObject *self, PyObject *args) {
    PyObject *method = PyObject_GetAttrString(self->wrapped, "setdefault");
    if (method == NULL) return NULL;
    PyObject *result = PyObject_Call(method, args, NULL);
    Py_DECREF(method);
    return result;
}

static PyObject *AuditedEnviron_update(AuditedEnvironObject *self, PyObject *args, PyObject *kwargs) {
    PyObject *method = PyObject_GetAttrString(self->wrapped, "update");
    if (method == NULL) return NULL;
    PyObject *result = PyObject_Call(method, args, kwargs);
    Py_DECREF(method);
    return result;
}

static PyObject *AuditedEnviron_clear(AuditedEnvironObject *self, PyObject *Py_UNUSED(ignored)) {
    return PyObject_CallMethod(self->wrapped, "clear", NULL);
}

// __iter__ support
static PyObject *AuditedEnviron_iter(AuditedEnvironObject *self) {
    return PyObject_GetIter(self->wrapped);
}

// __repr__
static PyObject *AuditedEnviron_repr(AuditedEnvironObject *self) {
    return PyObject_Repr(self->wrapped);
}

// __str__
static PyObject *AuditedEnviron_str(AuditedEnvironObject *self) {
    return PyObject_Str(self->wrapped);
}

// Methods
static PyMethodDef AuditedEnviron_methods[] = {
    {"get", (PyCFunction)AuditedEnviron_get, METH_VARARGS, "Get an environment variable."},
    {"keys", (PyCFunction)AuditedEnviron_keys, METH_NOARGS, "Return keys."},
    {"values", (PyCFunction)AuditedEnviron_values, METH_NOARGS, "Return values."},
    {"items", (PyCFunction)AuditedEnviron_items, METH_NOARGS, "Return items."},
    {"copy", (PyCFunction)AuditedEnviron_copy, METH_NOARGS, "Return a copy."},
    {"pop", (PyCFunction)AuditedEnviron_pop, METH_VARARGS, "Remove and return value."},
    {"setdefault", (PyCFunction)AuditedEnviron_setdefault, METH_VARARGS, "Set default value."},
    {"update", (PyCFunction)AuditedEnviron_update, METH_VARARGS | METH_KEYWORDS, "Update from dict."},
    {"clear", (PyCFunction)AuditedEnviron_clear, METH_NOARGS, "Clear all."},
    {NULL, NULL, 0, NULL}
};

// Destructor
static void AuditedEnviron_dealloc(AuditedEnvironObject *self) {
    Py_XDECREF(self->wrapped);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

// Type definition - using correct field order for GCC compatibility
static PyTypeObject AuditedEnvironType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "malwi_box.AuditedEnviron",
    .tp_basicsize = sizeof(AuditedEnvironObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor)AuditedEnviron_dealloc,
    .tp_repr = (reprfunc)AuditedEnviron_repr,
    .tp_as_sequence = &AuditedEnviron_as_sequence,
    .tp_as_mapping = &AuditedEnviron_as_mapping,
    .tp_str = (reprfunc)AuditedEnviron_str,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Audited environment wrapper",
    .tp_iter = (getiterfunc)AuditedEnviron_iter,
    .tp_methods = AuditedEnviron_methods,
};

// Create a new AuditedEnviron wrapping the given environ
static PyObject *AuditedEnviron_New(PyObject *wrapped) {
    AuditedEnvironObject *self = PyObject_New(AuditedEnvironObject, &AuditedEnvironType);
    if (self == NULL) {
        return NULL;
    }
    Py_INCREF(wrapped);
    self->wrapped = wrapped;
    return (PyObject *)self;
}

// =============================================================================
// Section 4: audited_getenv - C replacement for os.getenv
// =============================================================================

static PyObject *audited_getenv(PyObject *self, PyObject *args, PyObject *kwargs) {
    static char kw_key[] = "key";
    static char kw_default[] = "default";
    static char *kwlist[] = {kw_key, kw_default, NULL};
    PyObject *key, *default_val = Py_None;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", kwlist, &key, &default_val)) {
        return NULL;
    }

    // Fire audit event and set guard (so environ.get doesn't also fire)
    g_in_env_callback = 1;
    PyObject *event_args = PyTuple_Pack(1, key);
    if (event_args != NULL) {
        invoke_audit_callback("os.getenv", event_args);
        Py_DECREF(event_args);
    }

    // Call original getenv (which internally calls environ.get, but guard prevents double-fire)
    PyObject *call_args = PyTuple_Pack(2, key, default_val);
    if (call_args == NULL) {
        g_in_env_callback = 0;
        return NULL;
    }
    PyObject *result = PyObject_Call(g_os_getenv_original, call_args, NULL);
    Py_DECREF(call_args);
    g_in_env_callback = 0;
    return result;
}

static PyMethodDef audited_getenv_def = {
    "getenv",
    (PyCFunction)audited_getenv,
    METH_VARARGS | METH_KEYWORDS,
    "Get an environment variable (audited)."
};

// =============================================================================
// Section 5: Audit Hook Infrastructure
// =============================================================================

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

// =============================================================================
// Section 6: Profile Hook - HTTP/Encoding/Crypto Detection
// =============================================================================

// Frame function info for quick checks
typedef struct {
    const char *func_name;
    const char *filename;
    PyCodeObject *code;  // For cleanup
} FrameFuncInfo;

// Extract function info from frame (returns 0 on failure, 1 on success)
static int get_frame_func_info(PyFrameObject *frame, FrameFuncInfo *info) {
    info->code = PyFrame_GetCode(frame);
    if (info->code == NULL) return 0;

    PyObject *name_obj = info->code->co_name;
    PyObject *filename_obj = info->code->co_filename;

    if (name_obj == NULL || filename_obj == NULL) {
        Py_DECREF(info->code);
        return 0;
    }

    info->func_name = PyUnicode_AsUTF8(name_obj);
    info->filename = PyUnicode_AsUTF8(filename_obj);

    if (info->func_name == NULL || info->filename == NULL) {
        Py_DECREF(info->code);
        return 0;
    }

    return 1;
}

// Release frame function info
static void release_frame_func_info(FrameFuncInfo *info) {
    Py_DECREF(info->code);
}

// Fire an audit event with a single string argument
static void fire_simple_event(const char *event, const char *arg) {
    PyObject *arg_str = PyUnicode_FromString(arg);
    if (arg_str != NULL) {
        PyObject *args = PyTuple_Pack(1, arg_str);
        if (args != NULL) {
            invoke_audit_callback(event, args);
            Py_DECREF(args);
        }
        Py_DECREF(arg_str);
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
        const char *url_cstr = PyUnicode_AsUTF8(url_str);
        PyObject *final_url = NULL;

        // If URL is path-only (starts with /), try to build full URL from self
        if (url_cstr != NULL && url_cstr[0] == '/' && url_cstr[1] != '/') {
            PyObject *self_obj = get_local_item(locals, "self");
            if (self_obj != NULL) {
                // Try common attribute names for host
                PyObject *host = PyObject_GetAttrString(self_obj, "host");
                if (host == NULL) {
                    PyErr_Clear();
                    host = PyObject_GetAttrString(self_obj, "_host");
                }
                if (host != NULL && PyUnicode_Check(host)) {
                    const char *host_str = PyUnicode_AsUTF8(host);
                    if (host_str != NULL && host_str[0] != '\0') {
                        // Determine scheme
                        const char *scheme = "https";
                        PyObject *port = PyObject_GetAttrString(self_obj, "port");
                        if (port == NULL) {
                            PyErr_Clear();
                            port = PyObject_GetAttrString(self_obj, "_port");
                        }
                        long port_num = 0;
                        if (port != NULL && PyLong_Check(port)) {
                            port_num = PyLong_AsLong(port);
                            if (port_num == 80) scheme = "http";
                        }
                        Py_XDECREF(port);

                        // Build full URL
                        char url_buf[2048];
                        if (port_num > 0 && port_num != 80 && port_num != 443) {
                            snprintf(url_buf, sizeof(url_buf), "%s://%s:%ld%s",
                                     scheme, host_str, port_num, url_cstr);
                        } else {
                            snprintf(url_buf, sizeof(url_buf), "%s://%s%s",
                                     scheme, host_str, url_cstr);
                        }
                        final_url = PyUnicode_FromString(url_buf);
                    }
                }
                Py_XDECREF(host);
                Py_DECREF(self_obj);
            }
        }

        // Use original URL if we couldn't build a full one
        if (final_url == NULL) {
            final_url = url_str;
            Py_INCREF(final_url);
        }

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
            PyObject *args = PyTuple_Pack(2, final_url, method_str);
            if (args != NULL) {
                invoke_audit_callback("http.request", args);
                Py_DECREF(args);
            }
            Py_DECREF(method_str);
        }

        Py_DECREF(final_url);
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
    FrameFuncInfo info;
    if (!get_frame_func_info(frame, &info)) return;

    // Quick check: only interested in "urlopen" or "request" functions
    int is_http_func = 0;

    if (streq(info.func_name, "urlopen")) {
        // urllib.request.urlopen or urllib3 HTTPConnectionPool.urlopen
        if (strstr(info.filename, "urllib/request.py") != NULL ||
            strstr(info.filename, "urllib3/connectionpool.py") != NULL) {
            is_http_func = 1;
        }
    } else if (streq(info.func_name, "request")) {
        // requests Session.request, httpx Client.request, or http.client HTTPConnection.request
        if (strstr(info.filename, "requests/sessions.py") != NULL ||
            strstr(info.filename, "httpx/_client.py") != NULL ||
            strstr(info.filename, "http/client.py") != NULL) {
            is_http_func = 1;
        }
    } else if (streq(info.func_name, "_request")) {
        // aiohttp ClientSession._request
        if (strstr(info.filename, "aiohttp/client.py") != NULL) {
            is_http_func = 1;
        }
    }

    if (is_http_func) {
        if (strstr(info.filename, "http/client.py") != NULL) {
            extract_http_client_request(frame);
        } else {
            extract_and_report_http_request(frame);
        }
    }

    release_frame_func_info(&info);
}

// Check if current frame is an encoding function call (base64, binascii, compression)
static void check_encoding_function_call(PyFrameObject *frame) {
    FrameFuncInfo info;
    if (!get_frame_func_info(frame, &info)) return;

    // base64 module - check for encode/decode functions
    if (strstr(info.filename, "base64.py") != NULL) {
        if (strstr(info.func_name, "encode") != NULL ||
            strstr(info.func_name, "decode") != NULL) {
            fire_simple_event("encoding.base64", info.func_name);
        }
    }

    // hex encoding - binascii module
    if (strstr(info.filename, "binascii") != NULL) {
        if (streq(info.func_name, "hexlify") || streq(info.func_name, "b2a_hex")) {
            fire_simple_event("encoding.hex", "hexlify");
        } else if (streq(info.func_name, "unhexlify") || streq(info.func_name, "a2b_hex")) {
            fire_simple_event("encoding.hex", "unhexlify");
        }
    }

    // gzip compression - gzip.py module
    if (strstr(info.filename, "gzip.py") != NULL) {
        if (streq(info.func_name, "compress")) {
            fire_simple_event("encoding.gzip", "compress");
        } else if (streq(info.func_name, "decompress")) {
            fire_simple_event("encoding.gzip", "decompress");
        }
    }

    // zlib compression - C module, check for zlib in filename
    if (strstr(info.filename, "zlib") != NULL) {
        if (streq(info.func_name, "compress") || streq(info.func_name, "compressobj")) {
            fire_simple_event("encoding.zlib", "compress");
        } else if (streq(info.func_name, "decompress") || streq(info.func_name, "decompressobj")) {
            fire_simple_event("encoding.zlib", "decompress");
        }
    }

    // bz2 compression - check for bz2 in filename
    if (strstr(info.filename, "bz2") != NULL) {
        if (streq(info.func_name, "compress")) {
            fire_simple_event("encoding.bz2", "compress");
        } else if (streq(info.func_name, "decompress")) {
            fire_simple_event("encoding.bz2", "decompress");
        }
    }

    // lzma compression - check for lzma in filename
    if (strstr(info.filename, "lzma") != NULL) {
        if (streq(info.func_name, "compress")) {
            fire_simple_event("encoding.lzma", "compress");
        } else if (streq(info.func_name, "decompress")) {
            fire_simple_event("encoding.lzma", "decompress");
        }
    }

    release_frame_func_info(&info);
}

// Check if current frame is a crypto function call (cryptography library, hmac, secrets)
static void check_crypto_function_call(PyFrameObject *frame) {
    FrameFuncInfo info;
    if (!get_frame_func_info(frame, &info)) return;

    // cryptography library - cipher operations
    if (strstr(info.filename, "cryptography") != NULL &&
        strstr(info.filename, "ciphers") != NULL) {
        if (streq(info.func_name, "encryptor") || streq(info.func_name, "decryptor")) {
            fire_simple_event("crypto.cipher", info.func_name);
        }
    }

    // Fernet (high-level encryption)
    if (strstr(info.filename, "fernet.py") != NULL) {
        if (streq(info.func_name, "encrypt") || streq(info.func_name, "decrypt") ||
            streq(info.func_name, "encrypt_at_time") || streq(info.func_name, "decrypt_at_time")) {
            fire_simple_event("crypto.fernet", info.func_name);
        }
    }

    // hmac module
    if (strstr(info.filename, "hmac.py") != NULL) {
        if (streq(info.func_name, "new") || streq(info.func_name, "digest")) {
            fire_simple_event("crypto.hmac", info.func_name);
        }
    }

    // secrets module - secure random token generation
    if (strstr(info.filename, "secrets.py") != NULL) {
        if (streq(info.func_name, "token_bytes") ||
            streq(info.func_name, "token_hex") ||
            streq(info.func_name, "token_urlsafe")) {
            fire_simple_event("secrets.token", info.func_name);
        }
    }

    // cryptography RSA - check for rsa in path
    if (strstr(info.filename, "cryptography") != NULL &&
        strstr(info.filename, "rsa") != NULL) {
        if (streq(info.func_name, "generate_private_key") ||
            streq(info.func_name, "_generate_private_key")) {
            fire_simple_event("crypto.rsa", "generate");
        }
    }

    // cryptography AES - check for algorithms/ciphers with AES
    if (strstr(info.filename, "cryptography") != NULL) {
        // AES algorithm instantiation
        if (streq(info.func_name, "AES") || streq(info.func_name, "AES128") ||
            streq(info.func_name, "AES256")) {
            fire_simple_event("crypto.aes", "init");
        }
        // ChaCha20 algorithm instantiation
        if (streq(info.func_name, "ChaCha20") || streq(info.func_name, "ChaCha20Poly1305")) {
            fire_simple_event("crypto.chacha20", "init");
        }
    }

    release_frame_func_info(&info);
}

// Profile hook function for HTTP/encoding/crypto interception
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

    // Handle Python function calls (PyTrace_CALL) for HTTP/encoding/crypto interception
    if (what == PyTrace_CALL) {
        check_http_function_call(frame);
        check_encoding_function_call(frame);
        check_crypto_function_call(frame);
    }

    // Note: env var monitoring is handled by AuditedEnviron wrapper and audited_getenv,
    // not by PyTrace_C_CALL (which doesn't provide access to function arguments)

    return 0;
}

// =============================================================================
// Section 7: Module Interface (set_callback, clear_callback, set_blocklist)
// =============================================================================

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

        // Cache os module references and install audited wrappers BEFORE the audit hook
        // (because audit hook blocks sys.setprofile events)
        if (g_os_module == NULL) {
            g_os_module = PyImport_ImportModule("os");
            if (g_os_module != NULL) {
                // Save original getenv and environ
                g_os_getenv_original = PyObject_GetAttrString(g_os_module, "getenv");
                g_os_environ_original = PyObject_GetAttrString(g_os_module, "environ");

                // Initialize the AuditedEnviron type
                if (PyType_Ready(&AuditedEnvironType) >= 0) {
                    // Create and install audited environ wrapper
                    PyObject *audited_environ = AuditedEnviron_New(g_os_environ_original);
                    if (audited_environ != NULL) {
                        PyObject_SetAttrString(g_os_module, "environ", audited_environ);
                        Py_DECREF(audited_environ);
                    }
                }

                // Create and install audited getenv function
                PyObject *audited_getenv_func = PyCFunction_New(&audited_getenv_def, NULL);
                if (audited_getenv_func != NULL) {
                    PyObject_SetAttrString(g_os_module, "getenv", audited_getenv_func);
                    Py_DECREF(audited_getenv_func);
                }
            }
        }

        // Register profile hook for HTTP/encoding/crypto interception
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

// =============================================================================
// Section 8: Module Definition and Initialization
// =============================================================================

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
    Py_CLEAR(g_os_getenv_original);
    Py_CLEAR(g_os_environ_original);

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
