/**
 * malwi_python.c - Embedded Python wrapper with audit hook injection
 *
 * This program acts as a Python interpreter that injects the malwi-box
 * audit hook immediately after Python initialization. The actual security
 * blocking (sys.addaudithook, sys.setprofile, sys.settrace) is handled by
 * malwi_box.cpp when the Python-level hook is set up.
 *
 * Compile: gcc malwi_python.c -o malwi_python $(python3-config --cflags --ldflags --embed)
 *
 * Environment variables:
 *   MALWI_BOX_ENABLED=1  - Enable hook injection
 *   MALWI_BOX_MODE       - "run", "force", or "review" (default: "run")
 *   MALWI_BOX_CONFIG     - Path to config file (optional)
 *   MALWI_BOX_DEBUG=1    - Enable debug output
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// Forward declarations
static void inject_python_hook(void);

// Global state
static int g_hook_injected = 0;
static const char *g_mode = "run";

// Debug helper
static int is_debug_enabled(void) {
    const char *debug = getenv("MALWI_BOX_DEBUG");
    return debug && strcmp(debug, "1") == 0;
}

// Check if hook is enabled
static int is_hook_enabled(void) {
    const char *enabled = getenv("MALWI_BOX_ENABLED");
    return enabled && strcmp(enabled, "1") == 0;
}

/**
 * Inject the Python-level malwi-box hook
 */
static void inject_python_hook(void) {
    if (g_hook_injected) return;
    g_hook_injected = 1;

    int verbose = is_debug_enabled();
    if (verbose) fprintf(stderr, "[malwi_python] Injecting Python hook (mode=%s)\n", g_mode);

    const char *setup_func;
    if (strcmp(g_mode, "force") == 0) {
        setup_func = "setup_force_hook";
    } else if (strcmp(g_mode, "review") == 0) {
        setup_func = "setup_review_hook";
    } else {
        setup_func = "setup_run_hook";
    }

    // Build Python code to set up the hook
    char code[1024];
    const char *config_path = getenv("MALWI_BOX_CONFIG");
    if (config_path && config_path[0]) {
        snprintf(code, sizeof(code),
            "try:\n"
            "    from malwi_box.hook import %s\n"
            "    from malwi_box.engine import BoxEngine\n"
            "    engine = BoxEngine(config_path='%s')\n"
            "    %s(engine)\n"
            "except ImportError:\n"
            "    pass  # malwi_box not available\n",
            setup_func, config_path, setup_func);
    } else {
        snprintf(code, sizeof(code),
            "try:\n"
            "    from malwi_box.hook import %s\n"
            "    %s()\n"
            "except ImportError:\n"
            "    pass  # malwi_box not available\n",
            setup_func, setup_func);
    }

    int result = PyRun_SimpleString(code);
    if (verbose) {
        fprintf(stderr, "[malwi_python] Hook injection %s\n",
                result == 0 ? "succeeded" : "failed");
    }
}

/**
 * Convert char* argv to wchar_t* argv
 */
static wchar_t **convert_argv(int argc, char *argv[]) {
    wchar_t **wargv = (wchar_t **)malloc((argc + 1) * sizeof(wchar_t *));
    if (!wargv) return NULL;

    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]) + 1;
        wargv[i] = (wchar_t *)malloc(len * sizeof(wchar_t));
        if (!wargv[i]) {
            // Cleanup on failure
            for (int j = 0; j < i; j++) free(wargv[j]);
            free(wargv);
            return NULL;
        }
        mbstowcs(wargv[i], argv[i], len);
    }
    wargv[argc] = NULL;
    return wargv;
}

static void free_wargv(int argc, wchar_t **wargv) {
    if (!wargv) return;
    for (int i = 0; i < argc; i++) {
        free(wargv[i]);
    }
    free(wargv);
}

int main(int argc, char *argv[]) {
    int verbose = is_debug_enabled();

    // Get mode from environment
    const char *mode = getenv("MALWI_BOX_MODE");
    g_mode = mode ? mode : "run";

    if (verbose) {
        fprintf(stderr, "[malwi_python] Starting (enabled=%d, mode=%s)\n",
                is_hook_enabled(), g_mode);
    }

    // No C-level audit hook here - malwi_box.cpp handles all security blocking
    // (sys.addaudithook, sys.setprofile, sys.settrace) when inject_python_hook()
    // triggers the Python-level hook setup.

    // Convert arguments to wide characters
    wchar_t **wargv = convert_argv(argc, argv);
    if (!wargv) {
        fprintf(stderr, "[malwi_python] Failed to convert arguments\n");
        return 1;
    }

    // Configure Python
    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    // Set program name and arguments
    PyStatus status = PyConfig_SetArgv(&config, argc, wargv);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        free_wargv(argc, wargv);
        Py_ExitStatusException(status);
    }

    // Read configuration (populates paths, etc.)
    status = PyConfig_Read(&config);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        free_wargv(argc, wargv);
        Py_ExitStatusException(status);
    }

    // Initialize Python
    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    free_wargv(argc, wargv);

    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    if (verbose) {
        fprintf(stderr, "[malwi_python] Python initialized\n");
    }

    // Inject the Python-level hook now that Python is fully initialized
    if (is_hook_enabled()) {
        inject_python_hook();
    }

    // Run the main interpreter loop - this handles -c, -m, scripts, REPL
    // Py_RunMain() will handle command-line argument parsing and execution
    return Py_RunMain();
}
