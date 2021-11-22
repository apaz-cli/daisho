#ifndef __STILTS_STDLIB_PYTHON
#define __STILTS_STDLIB_PYTHON
#include "../StiltsStdInclude.h"
#if __STILTS_EMBED_PYTHON
#define PY_SSIZE_T_CLEAN
#include <Python.h>

static inline void
__Stilts_py_init() {
  Py_SetProgramName(argv[0]); 
  Py_Initialize();
  PyRun_SimpleString("from time import time,ctime\n"
                     "print 'Today is',ctime(time())\n");  
}

static inline void
__Stilts_py_exit() {
  Py_Finalize();
}

static inline void
__Stilts_py_eval(const char* evalStr) {
    
}

#endif /* __STILTS_EMBED_PYTHON */
#endif /* __STILTS_STDLIB_PYTHON */