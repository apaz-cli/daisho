#ifndef __DAI_STDLIB_SIGLIST
#define __DAI_STDLIB_SIGLIST
#include "../PreProcessor/PreProcessor.h"

/* http://www.skrenta.com/rt/man/signal.7.html */

typedef enum {
    __DAI_DSA_IGNO, /* Default action is to ignore the signal. */
    __DAI_DSA_CORE, /* Default action is to terminate the process and dump core. */
    __DAI_DSA_TERM, /* Default action is to terminate the process. */
    __DAI_DSA_STOP, /* Default action is to stop the process until it receives a continue signal. */
    __DAI_DSA_CONT, /* Default action is to continue the process from where it stopped. */
} __Dai_Default_Sigaction;

typedef struct {
    int code;
    __Dai_Default_Sigaction action;
    bool catchable;
    const char* name;
} __Dai_Siginfo;

const __Dai_Siginfo __Dai_siglist[] = {

    /*************************/
    /* 19 POSIX 1990 SIGNALS */
    /*************************/
    {SIGHUP, __DAI_DSA_TERM, true, "SIGHUP"},
    {SIGINT, __DAI_DSA_TERM, true, "SIGINT"},
    {SIGQUIT, __DAI_DSA_CORE, true, "SIGQUIT"},
    {SIGILL, __DAI_DSA_CORE, true, "SIGILL"},
    {SIGABRT, __DAI_DSA_CORE, true, "SIGABRT"},
    {SIGFPE, __DAI_DSA_CORE, true, "SIGFPE"},
    {SIGKILL, __DAI_DSA_TERM, false, "SIGKILL"},
    {SIGSEGV, __DAI_DSA_CORE, true, "SIGSEGV"},
    {SIGPIPE, __DAI_DSA_TERM, true, "SIGPIPE"},
    {SIGALRM, __DAI_DSA_TERM, true, "SIGALRM"},
    {SIGTERM, __DAI_DSA_TERM, true, "SIGTERM"},
    {SIGUSR1, __DAI_DSA_TERM, true, "SIGUSR1"},
    {SIGUSR2, __DAI_DSA_TERM, true, "SIGUSR2"},
    {SIGCHLD, __DAI_DSA_IGNO, true, "SIGCHLD"},
    {SIGCONT, __DAI_DSA_CONT, true, "SIGCONT"},
    {SIGSTOP, __DAI_DSA_STOP, false, "SIGSTOP"},
    {SIGTSTP, __DAI_DSA_STOP, true, "SIGTSTP"},
    {SIGTTIN, __DAI_DSA_STOP, true, "SIGTTIN"},
    {SIGTTOU, __DAI_DSA_STOP, true, "SIGTTOU"},

    /************************/
    /* 9 POSIX 2001 SIGNALS */
    /************************/
    {SIGBUS, __DAI_DSA_CORE, true, "SIGBUS"},
    {SIGPOLL, __DAI_DSA_TERM, true, "SIGPOLL"},
    {SIGPROF, __DAI_DSA_TERM, true, "SIGPROF"},
    {SIGSYS, __DAI_DSA_CORE, true, "SIGSYS"},
    {SIGTRAP, __DAI_DSA_CORE, true, "SIGTRAP"},
    {SIGURG, __DAI_DSA_IGNO, true, "SIGURG"},
    {SIGVTALRM, __DAI_DSA_TERM, true, "SIGVTALRM"},
    {SIGXCPU, __DAI_DSA_CORE, true, "SIGXCPU"},
    {SIGXFSZ, __DAI_DSA_CORE, true, "SIGXFSZ"},

/*********************************/
/* 10 POSSIBLE NON-POSIX SIGNALS */
/*********************************/
#ifdef SIGCLD
    {SIGCLD, __DAI_DSA_IGNO, true, "SIGCLD"},
#endif
#ifdef SIGEMT
    {SIGEMT, __DAI_DSA_CORE, true, "SIGEMT"},
#endif
#ifdef SIGINFO
    {SIGINFO, __DAI_DSA_TERM, true, "SIGINFO"},
#endif
#ifdef SIGIO
    {SIGIO, __DAI_DSA_TERM, true, "SIGIO"},
#endif
#ifdef SIGIOT
    {SIGIOT, __DAI_DSA_CORE, true, "SIGIOT"},
#endif
#ifdef SIGLOST
    {SIGLOST, __DAI_DSA_TERM, true, "SIGLOST"},
#endif
#ifdef SIGPWR
    {SIGPWR, __DAI_DSA_TERM, true, "SIGPWR"},
#endif
#ifdef SIGSTKFLT
    {SIGSTKFLT, __DAI_DSA_TERM, true, "SIGSTKFLT"},
#endif
#ifdef SIGUNUSED
    {SIGUNUSED, __DAI_DSA_CORE, true, "SIGUNUSED"},
#endif
#ifdef SIGWINCH
    {SIGWINCH, __DAI_DSA_IGNO, true, "SIGWINCH"},
#endif
};

#define __DAI_SIGLIST_LENGTH (sizeof(__Dai_siglist) / sizeof(__Dai_siglist[0]))

__DAI_FN const char*
__Dai_signal_to_str(int signal) {
    for (size_t i = 0; i < __DAI_SIGLIST_LENGTH; i++)
        if (__Dai_siglist[i].code == signal) return __Dai_siglist[i].name;

    if (__DAI_INSANE)
        __DAI_UNREACHABLE();
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

__DAI_FN void
__Dai_print_siglist(void) {
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
    for (size_t i = 0; i < __DAI_SIGLIST_LENGTH; i++) {
        __Dai_Siginfo sig = __Dai_siglist[i];
        printf(fmt, sig.name, sig.code, actions[sig.action], ft[sig.catchable]);
    }
    puts(startend);
}

#endif  // __DAI_STDLIB_SIGLIST
