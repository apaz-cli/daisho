#ifndef __STILTS_STDLIB_PYTHON
#define __STILTS_STDLIB_PYTHON

#include "../PreProcessor/StiltsPreprocessor.h"

/* No stdlib stuff in here. Only python. */

#if __STILTS_EMBED_PYTHON

__STILTS_FN void
Py_InitializeStilts(void)
{
    PyStatus status;

    status = _PyRuntime_Initialize();
    if (_PyStatus_EXCEPTION(status)) {
        Py_ExitStatusException(status);
    }
    _PyRuntimeState *runtime = &_PyRuntime;

    if (runtime->initialized) {
        /* bpo-33932: Calling Py_Initialize() twice does nothing. */
        return;
    }

    PyConfig config;
    _PyConfig_InitCompatConfig(&config);

    config.install_signal_handlers = 0;
    config.configure_c_stdio = 0;

    status = Py_InitializeFromConfig(&config);
    if (_PyStatus_EXCEPTION(status)) {
        Py_ExitStatusException(status);
    }
}


static wchar_t* __Stilts_py_progname = NULL;

__STILTS_FN void
__Stilts_py_init(int argc, char** argv) {
    (void)argc;

    /* Start the python interpreter */

    /* Wrestle control of print buffers away from Python. */
    if (unsetenv("PYTHONUNBUFFERED")) {
        fprintf(stderr, "Fatal error: Could not unset PYTHONUNBUFFERED environment variable to wrestle away control of the stdio buffers.");
    }
    __Stilts_py_progname = Py_DecodeLocale(argv[0], NULL);
    if (__Stilts_py_progname == NULL) {
        fprintf(stderr, "Fatal error: Python cannot decode argv[0].\n");
        exit(1);
    }

    Py_SetProgramName(__Stilts_py_progname);
    Py_Initialize();

    /* if it's null or undefined, we know that python set it unbuffered. */
    char* pybuf =  getenv("PYTHONUNBUFFERED");
    if (pybuf) {
        if (!pybuf[0])
            pybuf = NULL;
    }

    /* Do the dance to wrestle back control of the stdio buffers. */
    /* stdout */
    int saved = dup(1);
    fclose(stdout);
    dup(saved);
    close(saved);
    stdout = fdopen(1, "w");

    /* stdin */
    saved = dup(0);
    fclose(stdin);
    dup(saved);
    close(saved);
    stdin = fdopen(0, "w");

    /* stderr */
    saved = dup(2);
    fclose(stderr);
    dup(saved);
    close(saved);
    stderr = fdopen(2, "w");
}

__STILTS_FN void
__Stilts_py_exit(void) {
    /* Shut down the python interpreter */
    /* This should be the last thing that's done. */
    if (Py_FinalizeEx() < 0) exit(120);
    PyMem_RawFree(__Stilts_py_progname);
}

__STILTS_FN void
__Stilts_py_eval(char* to_eval) {
    PyRun_SimpleString(to_eval);
}

#else /* __STILTS_EMBED_PYTHON */

__STILTS_FN void
__Stilts_py_init(int argc, char** argv) {
    (void)argc;
    (void)argv;
}
__STILTS_FN void
__Stilts_py_exit(void) {}

__STILTS_FN void
__Stilts_py_eval(char* to_eval) {
    fprintf(stderr, "Cannot eval python code. Python is not enabled.\n");
}

#endif /* __STILTS_EMBED_PYTHON */
#endif /* __STILTS_STDLIB_PYTHON */
