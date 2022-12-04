#ifndef _DAI_STDLIB_PROFILE
#define _DAI_STDLIB_PROFILE

#include "../PreProcessor/PreProcessor.h"

#define _DAI_PROFILE 1

/* Profiling */

#ifndef _DAI_PROFILE_MEMDEBUG
#define _DAI_PROFILE_MEMDEBUG 0
#endif

#if _DAI_PROFILE_MEMDEBUG
#ifndef _DAI_PROFILE
#define _DAI_PROFILE 1
#endif
#else
#ifndef _DAI_PROFILE
#define _DAI_PROFILE 0
#endif
#endif

#if _DAI_PROFILE_MEMDEBUG && !_DAI_PROFILE
_Static_assert(0,
               "_DAI_PROFILE_MEMDEBUG = 1 is incompatible with _DAI_PROFILE "
               "= 0. Either use the debugger or don't.");
#endif

// Override the decision that it's not to be used with memdebug.

typedef enum {
    _DAI_STOPWATCH_HOURS,
    _DAI_STOPWATCH_MINUTES,
    _DAI_STOPWATCH_SECONDS,
    _DAI_STOPWATCH_MILLISECONDS,
    _DAI_STOPWATCH_MICROSECONDS,
} _Dai_StopwatchIncrement;

#if _DAI_PROFILE
static clock_t _Dai_stopwatch_timer;
static size_t _Dai_stopwatch_laps;
static double _Dai_stopwatch_resolution;
static char* _Dai_stopwatch_tstr;

static clock_t _Dai_stopwatch_start;
static clock_t _Dai_stopwatch_stop;

_DAI_FN void
_Dai_stopwatch_init(const _Dai_StopwatchIncrement resolution) {
    _Dai_stopwatch_timer = 0;
    _Dai_stopwatch_laps = 0;
    if (resolution == _DAI_STOPWATCH_HOURS) {
        _Dai_stopwatch_resolution = (CLOCKS_PER_SEC * 60 * 60);
        _Dai_stopwatch_tstr = (char*)"hours";
    } else if (resolution == _DAI_STOPWATCH_MINUTES) {
        _Dai_stopwatch_resolution = (CLOCKS_PER_SEC * 60);
        _Dai_stopwatch_tstr = (char*)"min";
    } else if (resolution == _DAI_STOPWATCH_SECONDS) {
        _Dai_stopwatch_resolution = (CLOCKS_PER_SEC);
        _Dai_stopwatch_tstr = (char*)"s";
    } else if (resolution == _DAI_STOPWATCH_MILLISECONDS) {
        _Dai_stopwatch_resolution = (CLOCKS_PER_SEC / 1000.0);
        _Dai_stopwatch_tstr = (char*)"ms";
    } else if (resolution == _DAI_STOPWATCH_MICROSECONDS) {
        _Dai_stopwatch_resolution = (CLOCKS_PER_SEC / 1000000.0);
        _Dai_stopwatch_tstr = (char*)"us";
    } else {
        fprintf(stdout,
                "Please provide a proper argument to "
                "_DAI_STOPWATCH_INIT().\n");
        exit(1);
    }
}
_DAI_FN void
_Dai_stopwatch_start_lap(void) {
    _Dai_stopwatch_start = clock();
}

_DAI_FN void
_Daisho_stopwatch_end_lap(void) {
    _Dai_stopwatch_stop = clock();
    _Dai_stopwatch_timer += (_Dai_stopwatch_stop - _Dai_stopwatch_start);
    _Dai_stopwatch_laps += 1;
}

_DAI_FN void
_Dai_stopwatch_read(void) {
    double __time_converted = (double)_Dai_stopwatch_timer / _Dai_stopwatch_resolution;
    double __avg_time =
        __time_converted / _Dai_stopwatch_laps; /* TODO figure out how to handle format and
                                                     * resolution. Probably with  preprocessor
                                                     * magic. Currently this only works on my
                                                     * machine. */
    if (_Dai_stopwatch_resolution != _DAI_STOPWATCH_MICROSECONDS) {
        printf(_DAI_COLOR_YELLOW "Stopwatch laps: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%zu" _DAI_COLOR_RESET "\n" _DAI_COLOR_YELLOW
                                     "Total Time: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%.2f %s" _DAI_COLOR_RESET "\n" _DAI_COLOR_YELLOW
                                     "Average Time: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%.2f %s" _DAI_COLOR_RESET "\n",
               _Dai_stopwatch_laps, __time_converted, _Dai_stopwatch_tstr, __avg_time,
               _Dai_stopwatch_tstr);
    } else {
        printf(_DAI_COLOR_YELLOW "Stopwatch laps: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%zu" _DAI_COLOR_RESET "\n" _DAI_COLOR_YELLOW
                                     "Total Time: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%.0f %s" _DAI_COLOR_RESET "\n" _DAI_COLOR_YELLOW
                                     "Average Time: " _DAI_COLOR_RESET _DAI_COLOR_RED
                                     "%.2f %s" _DAI_COLOR_RESET "\n",
               _Dai_stopwatch_laps, __time_converted, _Dai_stopwatch_tstr, __avg_time,
               _Dai_stopwatch_tstr);
    }
}

#define MICROBENCH_MAIN(function, times, resolution) \
    int main(void) {                                 \
        _DAI_STOPWATCH_INIT(resolution);         \
        for (size_t i = 0; i < (times); i++) {       \
            _DAI_STOPWATCH_START_LAP();          \
            function();                              \
            _DAI_STOPWATCH_END_LAP();            \
        }                                            \
        _DAI_STOPWATCH_READ();                   \
    }

#else  // _DAI_PROFILE

#define _DAI_STOPWATCH_INIT(resolution) ;
#define _DAI_STOPWATCH_START_LAP() ;
#define _DAI_STOPWATCH_END_LAP() ;
#define _DAI_STOPWATCH_READ() ;
#define MICROBENCH_MAIN(function, times, resolution)            \
    int main(void) {                                            \
        fprintf(stderr,                                         \
                "Profiling is disabled. Please recompile with " \
                "_DAI_PROFILE = 1 and MEMDEBUG = 0.\n");    \
        exit(1);                                                \
    }
#endif  // _DAI_PROFILE

#endif  // PROFILE_INCLUDE
