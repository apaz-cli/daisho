#ifndef __STILTS_STDLIB_PROFILE
#define __STILTS_STDLIB_PROFILE

#include "../PreProcessor/StiltsPreprocessor.h"

#define __STILTS_PROFILE 1

/* Profiling */

#ifndef __STILTS_PROFILE_MEMDEBUG
#define __STILTS_PROFILE_MEMDEBUG 0
#endif

#if __STILTS_PROFILE_MEMDEBUG
#ifndef __STILTS_PROFILE
#define __STILTS_PROFILE 1
#endif
#else
#ifndef __STILTS_PROFILE
#define __STILTS_PROFILE 0
#endif
#endif

#if __STILTS_PROFILE_MEMDEBUG && !__STILTS_PROFILE
_Static_assert(0,
               "__STILTS_PROFILE_MEMDEBUG = 1 is incompatible with __STILTS_PROFILE "
               "= 0. Either use the debugger or don't.");
#endif

// Override the decision that it's not to be used with memdebug.

typedef enum {
    __STILTS_STOPWATCH_HOURS,
    __STILTS_STOPWATCH_MINUTES,
    __STILTS_STOPWATCH_SECONDS,
    __STILTS_STOPWATCH_MILLISECONDS,
    __STILTS_STOPWATCH_MICROSECONDS,
} __Stilts_StopwatchIncrement;

#if __STILTS_PROFILE
static clock_t __Stilts_stopwatch_timer;
static size_t __Stilts_stopwatch_laps;
static double __Stilts_stopwatch_resolution;
static char* __Stilts_stopwatch_tstr;

static clock_t __Stilts_stopwatch_start;
static clock_t __Stilts_stopwatch_stop;

__STILTS_FN void
__Stilts_stopwatch_init(const __Stilts_StopwatchIncrement resolution) {
    __Stilts_stopwatch_timer = 0;
    __Stilts_stopwatch_laps = 0;
    if (resolution == __STILTS_STOPWATCH_HOURS) {
        __Stilts_stopwatch_resolution = (CLOCKS_PER_SEC * 60 * 60);
        __Stilts_stopwatch_tstr = "hours";
    } else if (resolution == __STILTS_STOPWATCH_MINUTES) {
        __Stilts_stopwatch_resolution = (CLOCKS_PER_SEC * 60);
        __Stilts_stopwatch_tstr = "min";
    } else if (resolution == __STILTS_STOPWATCH_SECONDS) {
        __Stilts_stopwatch_resolution = (CLOCKS_PER_SEC);
        __Stilts_stopwatch_tstr = "s";
    } else if (resolution == __STILTS_STOPWATCH_MILLISECONDS) {
        __Stilts_stopwatch_resolution = (CLOCKS_PER_SEC / 1000.0);
        __Stilts_stopwatch_tstr = "ms";
    } else if (resolution == __STILTS_STOPWATCH_MICROSECONDS) {
        __Stilts_stopwatch_resolution = (CLOCKS_PER_SEC / 1000000.0);
        __Stilts_stopwatch_tstr = "us";
    } else {
        fprintf(stdout,
                "Please provide a proper argument to "
                "__STILTS_STOPWATCH_INIT().\n");
        exit(1);
    }
}
__STILTS_FN void
__Stilts_stopwatch_start_lap(void) {
    __Stilts_stopwatch_start = clock();
}

__STILTS_FN void
_Stilts_stopwatch_end_lap(void) {
    __Stilts_stopwatch_stop = clock();
    __Stilts_stopwatch_timer += (__Stilts_stopwatch_stop - __Stilts_stopwatch_start);
    __Stilts_stopwatch_laps += 1;
}

__STILTS_FN void
__Stilts_stopwatch_read(void) {
    double __time_converted = (double)__Stilts_stopwatch_timer / __Stilts_stopwatch_resolution;
    double __avg_time =
        __time_converted / __Stilts_stopwatch_laps; /* TODO figure out how to handle format and
                                                     * resolution. Probably with  preprocessor
                                                     * magic. Currently this only works on my
                                                     * machine. */
    if (__Stilts_stopwatch_resolution != __STILTS_STOPWATCH_MICROSECONDS) {
        printf(__STILTS_COLOR_YELLOW "Stopwatch laps: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%zu" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_YELLOW
                                     "Total Time: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%.2f %s" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_YELLOW
                                     "Average Time: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%.2f %s" __STILTS_COLOR_RESET "\n",
               __Stilts_stopwatch_laps, __time_converted, __Stilts_stopwatch_tstr, __avg_time,
               __Stilts_stopwatch_tstr);
    } else {
        printf(__STILTS_COLOR_YELLOW "Stopwatch laps: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%zu" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_YELLOW
                                     "Total Time: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%.0f %s" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_YELLOW
                                     "Average Time: " __STILTS_COLOR_RESET __STILTS_COLOR_RED
                                     "%.2f %s" __STILTS_COLOR_RESET "\n",
               __Stilts_stopwatch_laps, __time_converted, __Stilts_stopwatch_tstr, __avg_time,
               __Stilts_stopwatch_tstr);
    }
}

#define MICROBENCH_MAIN(function, times, resolution) \
    int main(void) {                                 \
        __STILTS_STOPWATCH_INIT(resolution);         \
        for (size_t i = 0; i < (times); i++) {       \
            __STILTS_STOPWATCH_START_LAP();          \
            function();                              \
            __STILTS_STOPWATCH_END_LAP();            \
        }                                            \
        __STILTS_STOPWATCH_READ();                   \
    }

#else  // __STILTS_PROFILE

#define __STILTS_STOPWATCH_INIT(resolution) ;
#define __STILTS_STOPWATCH_START_LAP() ;
#define __STILTS_STOPWATCH_END_LAP() ;
#define __STILTS_STOPWATCH_READ() ;
#define MICROBENCH_MAIN(function, times, resolution)            \
    int main(void) {                                            \
        fprintf(stderr,                                         \
                "Profiling is disabled. Please recompile with " \
                "__STILTS_PROFILE = 1 and MEMDEBUG = 0.\n");    \
        exit(1);                                                \
    }
#endif  // __STILTS_PROFILE

#endif  // PROFILE_INCLUDE
