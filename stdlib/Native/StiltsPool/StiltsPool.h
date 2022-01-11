#pragma once
#ifndef __STILTS_STDLIB_POOL
#define __STILTS_STDLIB_POOL
#include "../StiltsAllocator/StiltsAllocator.h"
#include "StiltsMutex.h"

#define __STILTS_THREADPOOL_NUM_THREADS (__STILTS_IDEAL_NUM_THREADS - 1)
#define __STILTS_TASK_BUFFER_SIZE 512

/* Tasks */
typedef void (*__Stilts_Task_Fn)(void*);

typedef struct {
    __Stilts_Task_Fn fn;
    void* args;
} __Stilts_Task;

/* Circular queue for tasks. */
typedef struct {
    size_t front;
    size_t back;
    __Stilts_Task tasks[__STILTS_TASK_BUFFER_SIZE];
} __Stilts_Task_Queue;

/* Threadpool */
typedef struct {
    /* Protects the pool and task stack */
    __Stilts_Mutex pool_mutex;
    __Stilts_Task_Queue task_queue;

    /* Track the number of running threads so we know when we're finished. */
    size_t num_threads_running;
    pthread_t threads[__STILTS_THREADPOOL_NUM_THREADS];

    bool is_shutdown;
} __Stilts_Threadpool;

/* Initialize tne global shared threadpool containing a queue. Static
 * initialization is handled differently in C/C++. */

#ifndef __cplusplus
static __Stilts_Threadpool __Stilts_shared_pool = {
    .pool_mutex = __STILTS_MUTEX_INITIALIZER,
    .task_queue = {0},
    .num_threads_running = 0,
    .threads = {0},
    .is_shutdown = true};
#else /* __cplusplus */
static __Stilts_Threadpool __Stilts_shared_pool = {
    __STILTS_MUTEX_INITIALIZER, {}, 0, {}, true};
#endif

#define __Stilts_SHARED_POOL_CRITICAL_BEGIN() \
    __Stilts_mutex_lock(&(__Stilts_shared_pool.pool_mutex));
#define __Stilts_SHARED_POOL_CRITICAL_END() \
    __Stilts_mutex_unlock(&(__Stilts_shared_pool.pool_mutex));
#define __STILTS_TQUEUE __Stilts_shared_pool.task_queue

__STILTS_FN void __Stilts_shared_pool_submit(__Stilts_Task task);
__STILTS_FN __Stilts_Task __Stilts_shared_pool_take(void);
__STILTS_FN void* __Stilts_shared_pool_do_work(void* ignored);

__STILTS_FN void*
__Stilts_shared_pool_do_work(void* ignored) {
    (void)ignored;

    // Worker threads should kill themselves when they're done
    // This has no effect on the main thread, only ones started
    // with this function as an entry point in pthread_create().
    pthread_detach(pthread_self());

    // While there are tasks in the queue, do them.
    __Stilts_Task task;
    do {
        task = __Stilts_shared_pool_take();
        if (!task.fn) break;
        task.fn(task.args);
    } while (true);

    // Match the format required by pthread_create().
    return NULL;
}

/* Put tasks into the queue */
__STILTS_FN void
__Stilts_shared_pool_submit(__Stilts_Task task) {
    __Stilts_SHARED_POOL_CRITICAL_BEGIN();
    // Check for overflow
    if (((__STILTS_TQUEUE.back + 2) % __STILTS_TASK_BUFFER_SIZE) !=
        __STILTS_TQUEUE.front) {
        // No overflow, push onto queue
        __STILTS_TQUEUE.back =
            (__STILTS_TQUEUE.back + 1) % __STILTS_TASK_BUFFER_SIZE;
        __STILTS_TQUEUE.tasks[__STILTS_TQUEUE.back] = task;

        // While we have the mutex, if not already at capacity, start a thread
        // to do the work.
        if (__Stilts_shared_pool.num_threads_running <
            __STILTS_THREADPOOL_NUM_THREADS) {
            pthread_t* thread = __Stilts_shared_pool.threads +
                                __Stilts_shared_pool.num_threads_running;
            if (!pthread_create(thread, NULL, __Stilts_shared_pool_do_work,
                                NULL) &&
                __STILTS_SANITY_CHECK == 2)
                __STILTS_SANITY_FAIL();
        }

        __Stilts_SHARED_POOL_CRITICAL_END();
    } else {
        // When we can't queue a task, just do it. This not only eliminates the
        // failure case, but also relieves congestion on the mutex.
        __Stilts_SHARED_POOL_CRITICAL_END();
        task.fn(task.args);
    }
}

__STILTS_FN __Stilts_Task
__Stilts_shared_pool_take(void) {
    __Stilts_SHARED_POOL_CRITICAL_BEGIN();
    // Check if empty
    if (((__STILTS_TQUEUE.back + 1) % __STILTS_TASK_BUFFER_SIZE) !=
        __STILTS_TQUEUE.front) {
        // Not empty, grab task from front of queue and return.
        __Stilts_Task p = __STILTS_TQUEUE.tasks[__STILTS_TQUEUE.front];
        __STILTS_TQUEUE.front =
            (__STILTS_TQUEUE.front + 1) % __STILTS_TASK_BUFFER_SIZE;

        __Stilts_SHARED_POOL_CRITICAL_END();
        return p;
    } else {
        // Queue is empty, return nothing.
        __Stilts_SHARED_POOL_CRITICAL_END();
        __Stilts_Task task = {NULL, NULL};
        return task;
    }
}

#endif /* __STILTS_STDLIB_POOL */
