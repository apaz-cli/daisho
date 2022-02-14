#ifndef __DAI_STDLIB_PYTHON
#define __DAI_STDLIB_PYTHON

#include "../PreProcessor/DaishoPreprocessor.h"

/* No stdlib stuff in here. Only python. */

#if __DAI_EMBED_PYTHON

__DAI_FN void
__Dai_py_init(int argc, char** argv) {

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

__DAI_FN void
__Dai_py_exit(void) {
    /* Shut down the python interpreter */
    /* This should be the last thing that's done. */
    if (Py_FinalizeEx() < 0) {
        fprintf(stdout, "Failed to shut down the python interpreter.\n")
        exit(120);
    }
    exit(0);
}

__DAI_FN void
__Dai_py_eval(char* to_eval) {
    PyRun_SimpleString(to_eval);
}

#else /* __DAI_EMBED_PYTHON */

__DAI_FN void
__Dai_py_init(int argc, char** argv) {
    (void)argc;
    (void)argv;
}
__DAI_FN void
__Dai_py_exit(void) {}

__DAI_FN void
__Dai_py_eval(char* to_eval) {
    fprintf(stderr, "Cannot eval python code. Python is not enabled.\n");
}

#endif /* __DAI_EMBED_PYTHON */
#endif /* __DAI_STDLIB_PYTHON */
