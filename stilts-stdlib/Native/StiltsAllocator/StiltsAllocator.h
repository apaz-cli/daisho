#ifndef STILTS_STDLIB_ALLOCATOR
#define STILTS_STDLIB_ALLOCATOR
#include "../StiltsStdInclude.h"

#define SRC_INFO          __LINE__,    __func__,         __FILE__
#define SRC_INFO_ARGS     size_t line, const char* func, const char* file
#define SRC_INFO_IGNORE() (void)line;  (void)func;       (void)file:

/* Wrap malloc(), realloc(), and free(). */

static inline void* original_malloc (size_t size)            { return malloc (size);      }
static inline void* original_realloc(void* ptr, size_t size) { return realloc(ptr, size); }
static inline void  original_free   (void* ptr)              {        free   (ptr);       }

/* Decide what to do with these in the future. */
static inline void* stilts_malloc   (size_t size,            SRC_INFO_ARGS) \
                                    { SRC_INFO_IGNORE(); return original_malloc (size);      }
static inline void* stilts_realloc  (void* ptr, size_t size, SRC_INFO_ARGS) \
                                    { SRC_INFO_IGNORE(); return original_realloc(ptr, size); }
static inline void  stilts_free     (void* ptr,              SRC_INFO_ARGS) \
                                    { SRC_INFO_IGNORE();        original_free   (ptr);       }


#define malloc (size)      stilts_malloc (size,      SRC_INFO)
#define realloc(ptr, size) stilts_realloc(ptr, size, SRC_INFO)
#define free   (ptr)       stilts_free   (ptr,       SRC_INFO)


#endif /* STILTS_STDLIB_ALLOCATOR */
