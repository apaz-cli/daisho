#pragma once
#ifndef _DAI_STDLIB_MUTEX
#define _DAI_STDLIB_MUTEX
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

/*********/
/* MUTEX */
/*********/

#define _Dai_Mutex pthread_mutex_t
#define _DAI_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

// TODO: Rethink how to handle errors here.
_DAI_FN void
_Dai_mutex_init(_Dai_Mutex* mutex) {
    const char errmsg[] = "Could not initialize a mutex.";
    _DAI_SANE_ASSERT(!pthread_mutex_init(mutex, NULL), errmsg);
}
_DAI_FN void
_Dai_mutex_lock(_Dai_Mutex* mutex) {
    const char errmsg[] = "Could not lock a mutex.";
    _DAI_SANE_ASSERT(!pthread_mutex_lock(mutex), errmsg);
}
_DAI_FN void
_Dai_mutex_unlock(_Dai_Mutex* mutex) {
    const char errmsg[] = "Could not unlock a mutex.";
    _DAI_SANE_ASSERT(!pthread_mutex_unlock(mutex), errmsg);
}
_DAI_FN void
_Dai_mutex_destroy(_Dai_Mutex* mutex) {
    const char errmsg[] = "Could not initialize a mutex.";
    _DAI_SANE_ASSERT(!pthread_mutex_destroy(mutex), errmsg);
}

/**********/
/* RWLOCK */
/**********/

#define _Dai_rwlock_t pthread_rwlock_t
#define _DAI_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

_DAI_FN void
_Dai_rwlock_init(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not initialize a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_init(rwlock, NULL), errmsg);
}

_DAI_FN void
_Dai_rwlock_read_lock(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not acquire the read lock on a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_rdlock(rwlock), errmsg);
}
_DAI_FN void
_Dai_rwlock_write_lock(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not acquire the write lock on a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_wrlock(rwlock), errmsg);
}
_DAI_FN void
_Dai_rwlock_read_unlock(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not unlock the read lock on a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_unlock(rwlock), errmsg);
}
_DAI_FN void
_Dai_rwlock_write_unlock(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not unlock the write lock on a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_unlock(rwlock), errmsg);
}
_DAI_FN void
_Dai_rwlock_destroy(_Dai_rwlock_t* rwlock) {
    const char errmsg[] = "Could not destroy a rwlock.";
    _DAI_SANE_ASSERT(!pthread_rwlock_destroy(rwlock), errmsg);
}

#endif /* _DAI_STDLIB_MUTEX */
