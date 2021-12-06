#pragma once
#ifndef __STILTS_STDLIB_MUTEX
#define __STILTS_STDLIB_MUTEX

#include "../StiltsStdInclude.h"

/*********/
/* MUTEX */
/*********/

#define __Stilts_mutex_t pthread_mutex_t
#define __STILTS_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline void
__Stilts_mutex_init(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK) {
        if (!pthread_mutex_init(mutex, NULL)) 
    } else {
        pthread_mutex_init(mutex, NULL);
    }
}
static inline void
__Stilts_mutex_lock(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK) {
        pthread_mutex_lock(mutex);
    } else {
        pthread_mutex_lock(mutex);
    }
}
static inline void
__Stilts_mutex_unlock(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK) {
        pthread_mutex_unlock(mutex);
    } else {
        pthread_mutex_unlock(mutex);
    }
}
static inline void
__Stilts_mutex_destroy(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK) {
        pthread_mutex_destroy(mutex);
    } else {
        pthread_mutex_destroy(mutex);
    }
}

/**********/
/* RWLOCK */
/**********/

#define __Stilts_rwlock_t pthread_rwlock_t
#define __STILTS_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

static inline void
__Stilts_mutex_init(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_init(rwlock, NULL);
    } else {
        pthread_rwlock_init(rwlock, NULL);
    }
}

static inline void
__Stilts_rwlock_read_lock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_rdlock(rwlock);
    } else {
        pthread_rwlock_rdlock(rwlock);
    }
}
static inline void
__Stilts_rwlock_write_lock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_wrlock(rwlock);
    } else {
        pthread_rwlock_wrlock(rwlock);
    }
}
static inline void
__Stilts_rwlock_read_unlock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_unlock(rwlock);
    } else {
        pthread_rwlock_unlock(rwlock);
    }
}
static inline void
__Stilts_rwlock_write_unlock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_unlock(rwlock);
    } else {
        pthread_rwlock_unlock(rwlock);
    }
}
static inline void
__Stilts_rwlock_destroy(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK) {
        pthread_rwlock_destroy(rwlock);
    } else {
        pthread_rwlock_destroy(rwlock);
    }
}

#endif /* __STILTS_STDLIB_MUTEX */
