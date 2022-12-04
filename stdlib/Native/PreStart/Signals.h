#ifndef _DAI_STDLIB_SIGLIST
#define _DAI_STDLIB_SIGLIST
#include "../PreProcessor/PreProcessor.h"

/* http://www.skrenta.com/rt/man/signal.7.html */

typedef enum {
    _DAI_DSA_IGNO, /* Default action is to ignore the signal. */
    _DAI_DSA_CORE, /* Default action is to terminate the process and dump core. */
    _DAI_DSA_TERM, /* Default action is to terminate the process. */
    _DAI_DSA_STOP, /* Default action is to stop the process until it receives a continue signal. */
    _DAI_DSA_CONT, /* Default action is to continue the process from where it stopped. */
} _Dai_Default_Sigaction;

typedef struct {
    int code;
    _Dai_Default_Sigaction action;
    bool catchable;
    const char* name;
} _Dai_Siginfo;

const _Dai_Siginfo _Dai_siglist[] = {

    /*************************/
    /* 19 POSIX 1990 SIGNALS */
    /*************************/
    {SIGHUP, _DAI_DSA_TERM, true, "SIGHUP"},
    {SIGINT, _DAI_DSA_TERM, true, "SIGINT"},
    {SIGQUIT, _DAI_DSA_CORE, true, "SIGQUIT"},
    {SIGILL, _DAI_DSA_CORE, true, "SIGILL"},
    {SIGABRT, _DAI_DSA_CORE, true, "SIGABRT"},
    {SIGFPE, _DAI_DSA_CORE, true, "SIGFPE"},
    {SIGKILL, _DAI_DSA_TERM, false, "SIGKILL"},
    {SIGSEGV, _DAI_DSA_CORE, true, "SIGSEGV"},
    {SIGPIPE, _DAI_DSA_TERM, true, "SIGPIPE"},
    {SIGALRM, _DAI_DSA_TERM, true, "SIGALRM"},
    {SIGTERM, _DAI_DSA_TERM, true, "SIGTERM"},
    {SIGUSR1, _DAI_DSA_TERM, true, "SIGUSR1"},
    {SIGUSR2, _DAI_DSA_TERM, true, "SIGUSR2"},
    {SIGCHLD, _DAI_DSA_IGNO, true, "SIGCHLD"},
    {SIGCONT, _DAI_DSA_CONT, true, "SIGCONT"},
    {SIGSTOP, _DAI_DSA_STOP, false, "SIGSTOP"},
    {SIGTSTP, _DAI_DSA_STOP, true, "SIGTSTP"},
    {SIGTTIN, _DAI_DSA_STOP, true, "SIGTTIN"},
    {SIGTTOU, _DAI_DSA_STOP, true, "SIGTTOU"},

    /************************/
    /* 9 POSIX 2001 SIGNALS */
    /************************/
    {SIGBUS, _DAI_DSA_CORE, true, "SIGBUS"},
    {SIGPOLL, _DAI_DSA_TERM, true, "SIGPOLL"},
    {SIGPROF, _DAI_DSA_TERM, true, "SIGPROF"},
    {SIGSYS, _DAI_DSA_CORE, true, "SIGSYS"},
    {SIGTRAP, _DAI_DSA_CORE, true, "SIGTRAP"},
    {SIGURG, _DAI_DSA_IGNO, true, "SIGURG"},
    {SIGVTALRM, _DAI_DSA_TERM, true, "SIGVTALRM"},
    {SIGXCPU, _DAI_DSA_CORE, true, "SIGXCPU"},
    {SIGXFSZ, _DAI_DSA_CORE, true, "SIGXFSZ"},

/*********************************/
/* 10 POSSIBLE NON-POSIX SIGNALS */
/*********************************/
#ifdef SIGCLD
    {SIGCLD, _DAI_DSA_IGNO, true, "SIGCLD"},
#endif
#ifdef SIGEMT
    {SIGEMT, _DAI_DSA_CORE, true, "SIGEMT"},
#endif
#ifdef SIGINFO
    {SIGINFO, _DAI_DSA_TERM, true, "SIGINFO"},
#endif
#ifdef SIGIO
    {SIGIO, _DAI_DSA_TERM, true, "SIGIO"},
#endif
#ifdef SIGIOT
    {SIGIOT, _DAI_DSA_CORE, true, "SIGIOT"},
#endif
#ifdef SIGLOST
    {SIGLOST, _DAI_DSA_TERM, true, "SIGLOST"},
#endif
#ifdef SIGPWR
    {SIGPWR, _DAI_DSA_TERM, true, "SIGPWR"},
#endif
#ifdef SIGSTKFLT
    {SIGSTKFLT, _DAI_DSA_TERM, true, "SIGSTKFLT"},
#endif
#ifdef SIGUNUSED
    {SIGUNUSED, _DAI_DSA_CORE, true, "SIGUNUSED"},
#endif
#ifdef SIGWINCH
    {SIGWINCH, _DAI_DSA_IGNO, true, "SIGWINCH"},
#endif
};

#define _DAI_SIGLIST_LENGTH (sizeof(_Dai_siglist) / sizeof(_Dai_siglist[0]))

_DAI_FN const char*
_Dai_signal_to_str(int signal) {
    for (size_t i = 0; i < _DAI_SIGLIST_LENGTH; i++)
        if (_Dai_siglist[i].code == signal) return _Dai_siglist[i].name;

    if (_DAI_INSANE)
        _DAI_UNREACHABLE();
    else {
        const char* errmsg =
            "The signal you're looking for, number %i, could not be found in the signal list.\n"
            "Does it exist on this machine?\n"
            "A good place to start your search is '/usr/include/signal.h'.\n"
            "glibc puts them in x86_64-linux-gnu/asm/signal.h (or your arch target triple's "
            "equivalent).\n";
        fprintf(stderr, errmsg, signal);
        exit(1);
    }

    return NULL;
}

_DAI_FN void
_Dai_print_siglist(void) {
    // On stack, so not to clutter the binary.
    const char ign[] = "Ignore";
    const char dmp[] = "Dump Core";
    const char term[] = "Terminate";
    const char stop[] = "Stop";
    const char cont[] = "Continue";
    const char* actions[] = {ign, dmp, term, stop, cont};
    const char f[] = "False";
    const char t[] = "True";
    const char* ft[] = {f, t};
    const char startend[] = " X---------------------------------------------X";
    const char supported[] = " |             Supported Signals:              |";
    const char sep[] = " X-----------X---------X-----------X-----------X";
    const char labels[] = " |  Signal   | Number  |  Action   | Catchable |";
    const char fmt[] = " | %-9s | %7i | %9s | %9s |\n";

    puts(startend);
    puts(supported);
    puts(sep);
    puts(labels);
    puts(sep);
    for (size_t i = 0; i < _DAI_SIGLIST_LENGTH; i++) {
        _Dai_Siginfo sig = _Dai_siglist[i];
        printf(fmt, sig.name, sig.code, actions[sig.action], ft[sig.catchable]);
    }
    puts(startend);
}

#endif  // _DAI_STDLIB_SIGLIST
