#ifndef STILTS_STDLIB_POOL
#define STILTS_STDLIB_POOL
#include "../StiltsAllocator/StiltsAllocator.h"
#include "../StiltsStdInclude.h"
#include "StiltsMutex.h"

#define __STILTS_THREADPOOL_NUM_THREADS (__STILTS_IDEAL_NUM_THREADS - 1)

/*
 * Create a linked stack for tasks.
 */
typedef void (*__Stilts_Task_Fn)(void*);
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
        .num_threads_running = 0, .threads = {}                       \
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

static void* __Stilts_Threadpool_await_and_do_tasks(void* unused);

static inline void
__Stilts_Threadpool_start() {
    for (size_t i = 0; i < __STILTS_THREADPOOL_NUM_THREADS; i++)
        pthread_create(__Stilts_shared_pool.threads + i, NULL,
                       __Stilts_Threadpool_await_and_do_tasks, NULL);
}

// Add a task to the pool to be called with t
// Returns true on success, false on failure. Fails when pool is already shut
// down.
static inline bool
__Stilts_Threadpool_exectask(__Stilts_Task_Fn task_fn, void* task_args) {
    // Put the thread in the pool so that it can be consumed.
    __Stilts_THREADPOOL_CRITICAL_BEGIN;
    {
        // Fails if already shut down
        if (__Stilts_shared_pool.is_shutdown) return 0;

        // Push work onto the TaskStack
        __Stilts_TaskStack* work = (__Stilts_TaskStack*)__Stilts_malloc(
            sizeof(__Stilts_TaskStack), __STILTS_SRC_INFO);
        work->task.fn = task_fn;
        work->task.args = task_args;

        // Note that the TaskStack is initialized NULL.
        // Doing it this way makes sure the pool's TaskStack stays null
        // terminated.
        work->next = __Stilts_shared_pool.task_stack;
        __Stilts_shared_pool.task_stack = work;
    }
    __Stilts_THREADPOOL_CRITICAL_END;

    return 1;
}

static inline void*
__Stilts_Threadpool_await_and_do_tasks(void* unused) {
    (void)unused;

    // Detach self
    pthread_detach(pthread_self());

    // Wait for work and do it.
    while (true) {
        // Try to obtain work
        __Stilts_TaskStack* work = NULL;

        /* Critical section */
        __Stilts_THREADPOOL_CRITICAL_BEGIN;
        {
            // Join self when the pool shuts down,
            // making sure to end the critical section.
            if (__Stilts_shared_pool.is_shutdown &&
                __Stilts_shared_pool.task_stack == NULL) {
                __Stilts_shared_pool.num_threads_running--;
                __Stilts_THREADPOOL_CRITICAL_END;
                return NULL;
            }

            // Check for work. If we find some, pop it from the
            // stack and let the threadpool know that we're working on
            // something.

            work = __Stilts_shared_pool.task_stack;
            if (work) {
                __Stilts_shared_pool.task_stack = work->next;
            }
        }
        __Stilts_THREADPOOL_CRITICAL_END;

        if (work) {
            // Extract the work and args
            void (*task_fn)(void*) = work->task_fn;
            void* task_args = work->task_args;
            free(work);

            task_fn(task_args);
        } else {
            sched_yield();
            continue;
        }
    }
}

// Only destroy once, and not before the threadpool is created.
static inline void
Threadpool_destroy() {
    __Stilts_THREADPOOL_CRITICAL_BEGIN;
    __Stilts_shared_pool.is_shutdown = true;
    size_t waiting = (__Stilts_shared_pool.task_stack == NULL) |
                     __Stilts_shared_pool.num_threads_running;
    __Stilts_THREADPOOL_CRITICAL_END;

    // Wait for the task stack to be consumed and all tasks to finish running.

    while (waiting) {
        __Stilts_THREADPOOL_CRITICAL_BEGIN;
        waiting = (__Stilts_shared_pool.task_stack == NULL) |
                  __Stilts_shared_pool.num_threads_running;
        __Stilts_THREADPOOL_CRITICAL_END;

        sched_yield();
    }
}

#endif /* STILTS_STDLIB_POOL */