#ifndef __STILTS_STDLIB_MUTEX
#define __STILTS_STDLIB_MUTEX

#include "../StiltsStdInclude.h"

#define __Stilts_mutex_t pthread_mutex_t
#define __STILTS_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline int
__Stilts_mutex_init(__Stilts_mutex_t* mutex) {
    return pthread_mutex_init(mutex, NULL);
}
static inline int
__Stilts_mutex_lock(__Stilts_mutex_t* mutex) {
    return pthread_mutex_lock(mutex);
}
static inline int
__Stilts_mutex_unlock(__Stilts_mutex_t* mutex) {
    return pthread_mutex_unlock(mutex);
}
static inline int
__Stilts_mutex_destroy(__Stilts_mutex_t* mutex) {
    return pthread_mutex_destroy(mutex);
}

#endif /* __STILTS_STDLIB_MUTEX */