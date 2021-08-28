#ifndef MEMCONFIG
#define MEMCONFIG

// Either wrap malloc for debugging or for arena allocation.
#ifndef MEMDEBUG
#define MEMDEBUG 0
#endif
#ifndef PRINT_MEMALLOCS
#define PRINT_MEMALLOCS 0
#endif

#if MEMDEBUG == 0
#include "memdebug.h/memdebug.h"
#endif

#endif // MEMCONFIG