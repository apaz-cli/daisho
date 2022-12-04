#pragma once
#ifndef _DAI_STDLIB_POOL
#define _DAI_STDLIB_POOL
#include "../PreProcessor/PreProcessor.h"
#include "Mutex.h"
#include "Error.h"

#define _DAI_THREADPOOL_NUM_THREADS (_DAI_IDEAL_NUM_THREADS - 1)
#define _DAI_TASK_BUFFER_SIZE 512

/* Tasks */
typedef void (*_Dai_Task_Fn)(void*);

typedef struct {
    _Dai_Task_Fn fn;
    void* args;
} _Dai_Task;

/* Circular queue for tasks. */
typedef struct {
    size_t front;
    size_t back;
    _Dai_Task tasks[_DAI_TASK_BUFFER_SIZE];
} _Dai_Task_Queue;

/* Threadpool */
typedef struct {
    /* Protects the pool and task stack */
    _Dai_Mutex pool_mutex;
    _Dai_Task_Queue task_queue;

    /* Track the number of running threads so we know when we're finished. */
    size_t num_threads_running;
    pthread_t threads[_DAI_THREADPOOL_NUM_THREADS];

    bool is_shutdown;
} _Dai_Threadpool;

/* Initialize tne global shared threadpool containing a queue. Static
 * initialization is handled differently in C/C++. */

#ifndef __cplusplus
static _Dai_Threadpool _Dai_shared_pool = {.pool_mutex = _DAI_MUTEX_INITIALIZER,
                                                   .task_queue = {0},
                                                   .num_threads_running = 0,
                                                   .threads = {0},
                                                   .is_shutdown = true};
#else /* __cplusplus */
static _Dai_Threadpool _Dai_shared_pool = {_DAI_MUTEX_INITIALIZER, {}, 0, {}, true};
#endif

#define _Dai_SHARED_POOL_CRITICAL_BEGIN() \
    _Dai_mutex_lock(&(_Dai_shared_pool.pool_mutex));
#define _Dai_SHARED_POOL_CRITICAL_END() \
    _Dai_mutex_unlock(&(_Dai_shared_pool.pool_mutex));
#define _DAI_TQUEUE _Dai_shared_pool.task_queue

_DAI_FN void _Dai_shared_pool_submit(_Dai_Task task);
_DAI_FN _Dai_Task _Dai_shared_pool_take(void);
_DAI_FN void* _Dai_shared_pool_do_work(void* ignored);

_DAI_FN void*
_Dai_shared_pool_do_work(void* ignored) {
    (void)ignored;

    // Worker threads should kill themselves when they're done
    // This has no effect on the main thread, only ones started
    // with this function as an entry point in pthread_create().
    pthread_detach(pthread_self());

    // While there are tasks in the queue, do them.
    _Dai_Task task;
    do {
        task = _Dai_shared_pool_take();
        if (!task.fn) break;
        task.fn(task.args);
    } while (true);

    // Match the format required by pthread_create().
    return NULL;
}

/* Put tasks into the queue */
_DAI_FN void
_Dai_shared_pool_submit(_Dai_Task task) {
    int cannot_queue = 1;

    // Check if the queue would overflow
    _Dai_SHARED_POOL_CRITICAL_BEGIN();
    if (((_DAI_TQUEUE.back + 2) % _DAI_TASK_BUFFER_SIZE) != _DAI_TQUEUE.front) {
        // No overflow, push onto queue
        _DAI_TQUEUE.back = (_DAI_TQUEUE.back + 1) % _DAI_TASK_BUFFER_SIZE;
        _DAI_TQUEUE.tasks[_DAI_TQUEUE.back] = task;

        // Check if we're at thread capacity.
        if (_Dai_shared_pool.num_threads_running < _DAI_THREADPOOL_NUM_THREADS) {
            // If we're not, spin the thread.
            pthread_t* thread = _Dai_shared_pool.threads + _Dai_shared_pool.num_threads_running;
            cannot_queue = pthread_create(thread, NULL, _Dai_shared_pool_do_work, NULL);
        }

    }
    _Dai_SHARED_POOL_CRITICAL_END();


    // If we can't spin a thread to do the work, let's just do it ourselves.
    // This not only eliminates the failure case, but also relieves congestion on the mutex.
    if (cannot_queue) {
        task.fn(task.args);
    }
}

_DAI_FN _Dai_Task
_Dai_shared_pool_take(void) {
    _Dai_SHARED_POOL_CRITICAL_BEGIN();
    // Check if empty
    if (((_DAI_TQUEUE.back + 1) % _DAI_TASK_BUFFER_SIZE) != _DAI_TQUEUE.front) {
        // Not empty, grab task from front of queue and return.
        _Dai_Task p = _DAI_TQUEUE.tasks[_DAI_TQUEUE.front];
        _DAI_TQUEUE.front = (_DAI_TQUEUE.front + 1) % _DAI_TASK_BUFFER_SIZE;

        _Dai_SHARED_POOL_CRITICAL_END();
        return p;
    } else {
        // Queue is empty, return nothing.
        _Dai_SHARED_POOL_CRITICAL_END();
        _Dai_Task task = {NULL, NULL};
        return task;
    }
}

#endif /* _DAI_STDLIB_POOL */
