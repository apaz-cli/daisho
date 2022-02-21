#pragma once
#ifndef __DAI_STDLIB_MUTEX
#define __DAI_STDLIB_MUTEX
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

/*********/
/* MUTEX */
/*********/

#define __Dai_Mutex pthread_mutex_t
#define __DAI_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

// TODO: Rethink how to handle errors here.
__DAI_FN void
__Dai_mutex_init(__Dai_Mutex* mutex) {
    const char errmsg[] = "Could not initialize a mutex.";
    __DAI_SANE_ASSERT(!pthread_mutex_init(mutex, NULL), errmsg);
}
__DAI_FN void
__Dai_mutex_lock(__Dai_Mutex* mutex) {
    const char errmsg[] = "Could not lock a mutex.";
    __DAI_SANE_ASSERT(!pthread_mutex_lock(mutex), errmsg);
}
__DAI_FN void
__Dai_mutex_unlock(__Dai_Mutex* mutex) {
    const char errmsg[] = "Could not unlock a mutex.";
    __DAI_SANE_ASSERT(!pthread_mutex_unlock(mutex), errmsg);
}
__DAI_FN void
__Dai_mutex_destroy(__Dai_Mutex* mutex) {
    const char errmsg[] = "Could not initialize a mutex.";
    __DAI_SANE_ASSERT(!pthread_mutex_destroy(mutex), errmsg);
}

/**********/
/* RWLOCK */
/**********/

#define __Dai_rwlock_t pthread_rwlock_t
#define __DAI_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

__DAI_FN void
__Dai_rwlock_init(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not initialize a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_init(rwlock, NULL), errmsg);
}

__DAI_FN void
__Dai_rwlock_read_lock(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not acquire the read lock on a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_rdlock(rwlock), errmsg);
}
__DAI_FN void
__Dai_rwlock_write_lock(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not acquire the write lock on a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_wrlock(rwlock), errmsg);
}
__DAI_FN void
__Dai_rwlock_read_unlock(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not unlock the read lock on a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_unlock(rwlock), errmsg);
}
__DAI_FN void
__Dai_rwlock_write_unlock(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not unlock the write lock on a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_unlock(rwlock), errmsg);
}
__DAI_FN void
__Dai_rwlock_destroy(__Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not destroy a rwlock.";
    __DAI_SANE_ASSERT(!pthread_rwlock_destroy(rwlock), errmsg);
}

#endif /* __DAI_STDLIB_MUTEX */
