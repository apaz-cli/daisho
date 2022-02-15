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

__DAI_FN void
__Dai_mutex_init(__Dai_Mutex* mutex) {
    if (!pthread_mutex_init(mutex, NULL) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_mutex_lock(__Dai_Mutex* mutex) {
    if (!pthread_mutex_lock(mutex) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_mutex_unlock(__Dai_Mutex* mutex) {
    if (!pthread_mutex_unlock(mutex) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_mutex_destroy(__Dai_Mutex* mutex) {
    if (!pthread_mutex_destroy(mutex) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}

/**********/
/* RWLOCK */
/**********/

#define __Dai_rwlock_t pthread_rwlock_t
#define __DAI_RWLOCK_INITIALIZER PTHREAD_RWLOCK_INITIALIZER

__DAI_FN void
__Dai_rwlock_init(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_init(rwlock, NULL) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}

__DAI_FN void
__Dai_rwlock_read_lock(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_rdlock(rwlock) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_rwlock_write_lock(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_wrlock(rwlock) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_rwlock_read_unlock(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_unlock(rwlock) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_rwlock_write_unlock(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_unlock(rwlock) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}
__DAI_FN void
__Dai_rwlock_destroy(__Dai_rwlock_t* rwlock) {
    if (!pthread_rwlock_destroy(rwlock) && __DAI_SANITY_CHECK == 2) __DAI_SANITY_FAIL();
}

#endif /* __DAI_STDLIB_MUTEX */
