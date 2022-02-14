#pragma once
#ifndef __DAI_STDLIB_POOL
#define __DAI_STDLIB_POOL
#include "../PreProcessor/DaishoPreprocessor.h"
#include "DaishoMutex.h"

#define __DAI_THREADPOOL_NUM_THREADS (__DAI_IDEAL_NUM_THREADS - 1)
#define __DAI_TASK_BUFFER_SIZE 512

/* Tasks */
typedef void (*__Dai_Task_Fn)(void*);

typedef struct {
    __Dai_Task_Fn fn;
    void* args;
} __Dai_Task;

/* Circular queue for tasks. */
typedef struct {
    size_t front;
    size_t back;
    __Dai_Task tasks[__DAI_TASK_BUFFER_SIZE];
} __Dai_Task_Queue;

/* Threadpool */
typedef struct {
    /* Protects the pool and task stack */
    __Dai_Mutex pool_mutex;
    __Dai_Task_Queue task_queue;

    /* Track the number of running threads so we know when we're finished. */
    size_t num_threads_running;
    pthread_t threads[__DAI_THREADPOOL_NUM_THREADS];

    bool is_shutdown;
} __Dai_Threadpool;

/* Initialize tne global shared threadpool containing a queue. Static
 * initialization is handled differently in C/C++. */

#ifndef __cplusplus
static __Dai_Threadpool __Dai_shared_pool = {.pool_mutex = __DAI_MUTEX_INITIALIZER,
                                                   .task_queue = {0},
                                                   .num_threads_running = 0,
                                                   .threads = {0},
                                                   .is_shutdown = true};
#else /* __cplusplus */
static __Dai_Threadpool __Dai_shared_pool = {__DAI_MUTEX_INITIALIZER, {}, 0, {}, true};
#endif

#define __Dai_SHARED_POOL_CRITICAL_BEGIN() \
    __Dai_mutex_lock(&(__Dai_shared_pool.pool_mutex));
#define __Dai_SHARED_POOL_CRITICAL_END() \
    __Dai_mutex_unlock(&(__Dai_shared_pool.pool_mutex));
#define __DAI_TQUEUE __Dai_shared_pool.task_queue

__DAI_FN void __Dai_shared_pool_submit(__Dai_Task task);
__DAI_FN __Dai_Task __Dai_shared_pool_take(void);
__DAI_FN void* __Dai_shared_pool_do_work(void* ignored);

__DAI_FN void*
__Dai_shared_pool_do_work(void* ignored) {
    (void)ignored;

    // Worker threads should kill themselves when they're done
    // This has no effect on the main thread, only ones started
    // with this function as an entry point in pthread_create().
    pthread_detach(pthread_self());

    // While there are tasks in the queue, do them.
    __Dai_Task task;
    do {
        task = __Dai_shared_pool_take();
        if (!task.fn) break;
        task.fn(task.args);
    } while (true);

    // Match the format required by pthread_create().
    return NULL;
}

/* Put tasks into the queue */
__DAI_FN void
__Dai_shared_pool_submit(__Dai_Task task) {
    __Dai_SHARED_POOL_CRITICAL_BEGIN();
    // Check for overflow
    if (((__DAI_TQUEUE.back + 2) % __DAI_TASK_BUFFER_SIZE) != __DAI_TQUEUE.front) {
        // No overflow, push onto queue
        __DAI_TQUEUE.back = (__DAI_TQUEUE.back + 1) % __DAI_TASK_BUFFER_SIZE;
        __DAI_TQUEUE.tasks[__DAI_TQUEUE.back] = task;

        // While we have the mutex, if not already at capacity, start a thread
        // to do the work.
        if (__Dai_shared_pool.num_threads_running < __DAI_THREADPOOL_NUM_THREADS) {
            pthread_t* thread =
                __Dai_shared_pool.threads + __Dai_shared_pool.num_threads_running;
            if (!pthread_create(thread, NULL, __Dai_shared_pool_do_work, NULL) &&
                __DAI_SANITY_CHECK == 2)
                __DAI_SANITY_FAIL();
        }

        __Dai_SHARED_POOL_CRITICAL_END();
    } else {
        // When we can't queue a task, just do it. This not only eliminates the
        // failure case, but also relieves congestion on the mutex.
        __Dai_SHARED_POOL_CRITICAL_END();
        task.fn(task.args);
    }
}

__DAI_FN __Dai_Task
__Dai_shared_pool_take(void) {
    __Dai_SHARED_POOL_CRITICAL_BEGIN();
    // Check if empty
    if (((__DAI_TQUEUE.back + 1) % __DAI_TASK_BUFFER_SIZE) != __DAI_TQUEUE.front) {
        // Not empty, grab task from front of queue and return.
        __Dai_Task p = __DAI_TQUEUE.tasks[__DAI_TQUEUE.front];
        __DAI_TQUEUE.front = (__DAI_TQUEUE.front + 1) % __DAI_TASK_BUFFER_SIZE;

        __Dai_SHARED_POOL_CRITICAL_END();
        return p;
    } else {
        // Queue is empty, return nothing.
        __Dai_SHARED_POOL_CRITICAL_END();
        __Dai_Task task = {NULL, NULL};
        return task;
    }
}

#endif /* __DAI_STDLIB_POOL */
