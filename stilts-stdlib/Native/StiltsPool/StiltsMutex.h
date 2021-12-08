#pragma once
#ifndef __STILTS_STDLIB_MUTEX
#define __STILTS_STDLIB_MUTEX

#include "../StiltsStdInclude.h"

/*********/
/* MUTEX */
/*********/

#define __Stilts_mutex_t pthread_mutex_t
#define __STILTS_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

__STILTS_FN void
__Stilts_mutex_init(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_mutex_init(mutex, NULL)) __STILTS_SANITY_FAIL();
    } else {
        pthread_mutex_init(mutex, NULL);
    }
}
__STILTS_FN void
__Stilts_mutex_lock(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK == 2) {   
        if (!pthread_mutex_lock(mutex)) __STILTS_SANITY_FAIL();
    } else {
        pthread_mutex_lock(mutex);
    }
}
__STILTS_FN void
__Stilts_mutex_unlock(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_mutex_unlock(mutex)) __STILTS_SANITY_FAIL();
    } else {
        pthread_mutex_unlock(mutex);
    }
}
__STILTS_FN void
__Stilts_mutex_destroy(__Stilts_mutex_t* mutex) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_mutex_destroy(mutex)) __STILTS_SANITY_FAIL();
    } else {
        pthread_mutex_destroy(mutex);
    }
}

/**********/
/* RWLOCK */
/**********/

#define __Stilts_rwlock_t pthread_rwlock_t
#define __STILTS_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

__STILTS_FN void
__Stilts_rwlock_init(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_init(rwlock, NULL)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_init(rwlock, NULL);
    }
}

__STILTS_FN void
__Stilts_rwlock_read_lock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_rdlock(rwlock)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_rdlock(rwlock);
    }
}
__STILTS_FN void
__Stilts_rwlock_write_lock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_wrlock(rwlock)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_wrlock(rwlock);
    }
}
__STILTS_FN void
__Stilts_rwlock_read_unlock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_unlock(rwlock)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_unlock(rwlock);
    }
}
__STILTS_FN void
__Stilts_rwlock_write_unlock(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_unlock(rwlock)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_unlock(rwlock);
    }
}
__STILTS_FN void
__Stilts_rwlock_destroy(__Stilts_rwlock_t* rwlock) {
    if (__STILTS_SANITY_CHECK == 2) {
        if (!pthread_rwlock_destroy(rwlock)) __STILTS_SANITY_FAIL();
    } else {
        pthread_rwlock_destroy(rwlock);
    }
}

#endif /* __STILTS_STDLIB_MUTEX */
