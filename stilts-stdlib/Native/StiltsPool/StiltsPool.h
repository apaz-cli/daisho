#pragma once
#ifndef __STILTS_STDLIB_POOL
#define __STILTS_STDLIB_POOL
#include "../StiltsAllocator/StiltsAllocator.h"
#include "../StiltsStdInclude.h"
#include "StiltsMutex.h"

#define __STILTS_THREADPOOL_NUM_THREADS (__STILTS_IDEAL_NUM_THREADS - 1)

/*
 * Tasks submitted to the pool will be in the following form.
 * This way, they get to decide their own way to handle IO.
 */
typedef void (*__Stilts_Task_Fn)(void*);

/*
 * Create a circular queue for tasks.
 */
typedef struct {
    __Stilts_Task_Fn fn;
    void* args;
} __Stilts_Task;
typedef struct {
    __Stilts_Task* Tasks;
    size_t size;
    size_t cap;
} __Stilts_Task_List;

struct __Stilts_TaskStack;
typedef struct __Stilts_TaskStack __Stilts_TaskStack;
struct __Stilts_TaskStack {
    __Stilts_Task task;
    __Stilts_TaskStack* next;
};

typedef struct {
    /* Protects the pool and task stack */
    __Stilts_mutex_t pool_mutex;
    __Stilts_TaskStack* task_stack;

    /* Track the number of running threads so we know when we're finished. */
    size_t num_threads_running;
    pthread_t threads[__STILTS_THREADPOOL_NUM_THREADS];

    bool is_shutdown;
} __Stilts_Threadpool;

#define __STILTS_SHARED_POOL_INITIALIZER                              \
    {                                                                 \
        .pool_mutex = __STILTS_MUTEX_INITIALIZER, .task_stack = NULL, \
        .num_threads_running = 0, .threads = {}, .is_shutdown = true  \
    }

/*
 * Define one shared global threadpool.
 */
static __Stilts_Threadpool __Stilts_shared_pool =
    __STILTS_SHARED_POOL_INITIALIZER;

#define __Stilts_THREADPOOL_CRITICAL_BEGIN \
    __Stilts_mutex_lock(&(__Stilts_shared_pool.pool_mutex));
#define __Stilts_THREADPOOL_CRITICAL_END \
    __Stilts_mutex_unlock(&(__Stilts_shared_pool.pool_mutex));

#endif /* __STILTS_STDLIB_POOL */
