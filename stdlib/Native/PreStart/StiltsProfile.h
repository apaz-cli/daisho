#ifndef __DAI_STDLIB_PROFILE
#define __DAI_STDLIB_PROFILE

#include "../PreProcessor/DaishoPreprocessor.h"

#define __DAI_PROFILE 1

/* Profiling */

#ifndef __DAI_PROFILE_MEMDEBUG
#define __DAI_PROFILE_MEMDEBUG 0
#endif

#if __DAI_PROFILE_MEMDEBUG
#ifndef __DAI_PROFILE
#define __DAI_PROFILE 1
#endif
#else
#ifndef __DAI_PROFILE
#define __DAI_PROFILE 0
#endif
#endif

#if __DAI_PROFILE_MEMDEBUG && !__DAI_PROFILE
_Static_assert(0,
               "__DAI_PROFILE_MEMDEBUG = 1 is incompatible with __DAI_PROFILE "
               "= 0. Either use the debugger or don't.");
#endif

// Override the decision that it's not to be used with memdebug.

typedef enum {
    __DAI_STOPWATCH_HOURS,
    __DAI_STOPWATCH_MINUTES,
    __DAI_STOPWATCH_SECONDS,
    __DAI_STOPWATCH_MILLISECONDS,
    __DAI_STOPWATCH_MICROSECONDS,
} __Dai_StopwatchIncrement;

#if __DAI_PROFILE
static clock_t __Dai_stopwatch_timer;
static size_t __Dai_stopwatch_laps;
static double __Dai_stopwatch_resolution;
static char* __Dai_stopwatch_tstr;

static clock_t __Dai_stopwatch_start;
static clock_t __Dai_stopwatch_stop;

__DAI_FN void
__Dai_stopwatch_init(const __Dai_StopwatchIncrement resolution) {
    __Dai_stopwatch_timer = 0;
    __Dai_stopwatch_laps = 0;
    if (resolution == __DAI_STOPWATCH_HOURS) {
        __Dai_stopwatch_resolution = (CLOCKS_PER_SEC * 60 * 60);
        __Dai_stopwatch_tstr = "hours";
    } else if (resolution == __DAI_STOPWATCH_MINUTES) {
        __Dai_stopwatch_resolution = (CLOCKS_PER_SEC * 60);
        __Dai_stopwatch_tstr = "min";
    } else if (resolution == __DAI_STOPWATCH_SECONDS) {
        __Dai_stopwatch_resolution = (CLOCKS_PER_SEC);
        __Dai_stopwatch_tstr = "s";
    } else if (resolution == __DAI_STOPWATCH_MILLISECONDS) {
        __Dai_stopwatch_resolution = (CLOCKS_PER_SEC / 1000.0);
        __Dai_stopwatch_tstr = "ms";
    } else if (resolution == __DAI_STOPWATCH_MICROSECONDS) {
        __Dai_stopwatch_resolution = (CLOCKS_PER_SEC / 1000000.0);
        __Dai_stopwatch_tstr = "us";
    } else {
        fprintf(stdout,
                "Please provide a proper argument to "
                "__DAI_STOPWATCH_INIT().\n");
        exit(1);
    }
}
__DAI_FN void
__Dai_stopwatch_start_lap(void) {
    __Dai_stopwatch_start = clock();
}

__DAI_FN void
_Daisho_stopwatch_end_lap(void) {
    __Dai_stopwatch_stop = clock();
    __Dai_stopwatch_timer += (__Dai_stopwatch_stop - __Dai_stopwatch_start);
    __Dai_stopwatch_laps += 1;
}

__DAI_FN void
__Dai_stopwatch_read(void) {
    double __time_converted = (double)__Dai_stopwatch_timer / __Dai_stopwatch_resolution;
    double __avg_time =
        __time_converted / __Dai_stopwatch_laps; /* TODO figure out how to handle format and
                                                     * resolution. Probably with  preprocessor
                                                     * magic. Currently this only works on my
                                                     * machine. */
    if (__Dai_stopwatch_resolution != __DAI_STOPWATCH_MICROSECONDS) {
        printf(__DAI_COLOR_YELLOW "Stopwatch laps: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%zu" __DAI_COLOR_RESET "\n" __DAI_COLOR_YELLOW
                                     "Total Time: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%.2f %s" __DAI_COLOR_RESET "\n" __DAI_COLOR_YELLOW
                                     "Average Time: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%.2f %s" __DAI_COLOR_RESET "\n",
               __Dai_stopwatch_laps, __time_converted, __Dai_stopwatch_tstr, __avg_time,
               __Dai_stopwatch_tstr);
    } else {
        printf(__DAI_COLOR_YELLOW "Stopwatch laps: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%zu" __DAI_COLOR_RESET "\n" __DAI_COLOR_YELLOW
                                     "Total Time: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%.0f %s" __DAI_COLOR_RESET "\n" __DAI_COLOR_YELLOW
                                     "Average Time: " __DAI_COLOR_RESET __DAI_COLOR_RED
                                     "%.2f %s" __DAI_COLOR_RESET "\n",
               __Dai_stopwatch_laps, __time_converted, __Dai_stopwatch_tstr, __avg_time,
               __Dai_stopwatch_tstr);
    }
}

#define MICROBENCH_MAIN(function, times, resolution) \
    int main(void) {                                 \
        __DAI_STOPWATCH_INIT(resolution);         \
        for (size_t i = 0; i < (times); i++) {       \
            __DAI_STOPWATCH_START_LAP();          \
            function();                              \
            __DAI_STOPWATCH_END_LAP();            \
        }                                            \
        __DAI_STOPWATCH_READ();                   \
    }

#else  // __DAI_PROFILE

#define __DAI_STOPWATCH_INIT(resolution) ;
#define __DAI_STOPWATCH_START_LAP() ;
#define __DAI_STOPWATCH_END_LAP() ;
#define __DAI_STOPWATCH_READ() ;
#define MICROBENCH_MAIN(function, times, resolution)            \
    int main(void) {                                            \
        fprintf(stderr,                                         \
                "Profiling is disabled. Please recompile with " \
                "__DAI_PROFILE = 1 and MEMDEBUG = 0.\n");    \
        exit(1);                                                \
    }
#endif  // __DAI_PROFILE

#endif  // PROFILE_INCLUDE
