#ifndef _DAI_STDLIB_PYTHON
#define _DAI_STDLIB_PYTHON

#include "../PreProcessor/PreProcessor.h"

/* No stdlib stuff in here. Only python. */

#if _DAI_EMBED_PYTHON

_DAI_FN void
_Dai_py_init(int argc, char** argv) {

    /* Create a status and config. */
    PyStatus status;
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);

    /* Set the config not to hijack the C runtime. (That's our job) */
    /* These are already set by PyConfig_InitIsolatedConfig(). */
    /* config.isolated = 1; config.install_signal_handlers = 0; config.configure_c_stdio = 0; */
    config.optimization_level = 1;

    /* (Note that, upon fatal errors, it is acceptable to use the print buffers). */

    /* Decode command line arguments. */
    status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (PyStatus_Exception(status)) {
        fprintf(stderr, "Fatal error: Python cannot decode command line arguments.\n");
        Py_ExitStatusException(status);
    }

    /* Start the python interpreter */
    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        fprintf(stderr, "Fatal error: Python cannot initialize.\n");
        Py_ExitStatusException(status);
    }

    /* Free the memory taken up by the config. */
    PyConfig_Clear(&config);
}

_DAI_FN void
_Dai_py_exit(void) {
    /* Shut down the python interpreter */
    /* This should be the last thing that's done. */
    if (Py_FinalizeEx() < 0) {
        fprintf(stdout, "Failed to shut down the python interpreter.\n");
        exit(120);
    }
    exit(0);
}

_DAI_FN void
_Dai_py_eval(char* to_eval) {
    PyRun_SimpleString(to_eval);
}

#else /* _DAI_EMBED_PYTHON */

_DAI_FN void
_Dai_py_init(int argc, char** argv) {
    (void)argc;
    (void)argv;
}
_DAI_FN void
_Dai_py_exit(void) {}

_DAI_FN void
_Dai_py_eval(char* to_eval) {
    (void)to_eval;
    fprintf(stderr, "Cannot eval python code. Python is not enabled.\n");
}

#endif /* _DAI_EMBED_PYTHON */
#endif /* _DAI_STDLIB_PYTHON */
