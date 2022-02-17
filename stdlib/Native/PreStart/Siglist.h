#ifndef SIGLIST_H_INCLUDED
#define SIGLIST_H_INCLUDED
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
    const char* description;
} __Dai_Siginfo;

const __Dai_Siginfo __Dai_siglist[] = {

    /**********************/
    /* POSIX 1990 SIGNALS */
    /**********************/
    {SIGHUP, __DAI_DSA_TERM, true, "SIGHUP", "Controlling system hung up"},
    {SIGINT, __DAI_DSA_TERM, true, "SIGINT", "Interrupt from keyboard"},
    {SIGQUIT, __DAI_DSA_CORE, true, "SIGQUIT", "Quit from keyboard"},
    {SIGILL, __DAI_DSA_CORE, true, "SIGILL", "Illegal Instruction"},
    {SIGABRT, __DAI_DSA_CORE, true, "SIGABRT", "Abort signal"},
    {SIGFPE, __DAI_DSA_CORE, true, "SIGFPE", "Floating-point exception"},
    {SIGKILL, __DAI_DSA_TERM, false, "SIGKILL", "Kill signal"},
    {SIGSEGV, __DAI_DSA_CORE, true, "SIGSEGV", "Segmentation fault"},
    {SIGPIPE, __DAI_DSA_TERM, true, "SIGPIPE", "Broken pipe: write to pipe with no readers"},
    {SIGALRM, __DAI_DSA_TERM, true, "SIGALRM", "Timer signal"},
    {SIGTERM, __DAI_DSA_TERM, true, "SIGTERM", "Termination signal"},
    {SIGUSR1, __DAI_DSA_TERM, true, "SIGUSR1", "User-defined signal 1"},
    {SIGUSR2, __DAI_DSA_TERM, true, "SIGUSR2", "User-defined signal 2"},
    {SIGCHLD, __DAI_DSA_IGNO, true, "SIGCHLD", "Child stopped or terminated"},
    {SIGCONT, __DAI_DSA_CONT, true, "SIGCONT", "Continue if stopped"},
    {SIGSTOP, __DAI_DSA_STOP, false, "SIGSTOP", "Stop process"},
    {SIGTSTP, __DAI_DSA_STOP, true, "SIGTSTP", "Stop typed at terminal"},
    {SIGTTIN, __DAI_DSA_STOP, true, "SIGTTIN", "Terminal input for background process"},
    {SIGTTOU, __DAI_DSA_STOP, true, "SIGTTOU", "Terminal output for background process"},

    /**********************/
    /* POSIX 2001 SIGNALS */
    /**********************/
    {SIGBUS, __DAI_DSA_CORE, true, "SIGBUS", "Bus error (bad memory access)"},
    {SIGPOLL, __DAI_DSA_TERM, true, "SIGPOLL", "Pollable event: I/O now possible"},
    {SIGPROF, __DAI_DSA_TERM, true, "SIGPROF", "Profiling timer expired"},
    {SIGSYS, __DAI_DSA_CORE, true, "SIGSYS", "Bad system call"},
    {SIGTRAP, __DAI_DSA_CORE, true, "SIGTRAP", "Trace/breakpoint trap"},
    {SIGURG, __DAI_DSA_IGNO, true, "SIGURG", "Urgent condition on socket "},
    {SIGVTALRM, __DAI_DSA_TERM, true, "SIGVTALRM", "Process CPU timer expired."},
    {SIGXCPU, __DAI_DSA_CORE, true, "SIGXCPU", "CPU time limit exceeded "},
    {SIGXFSZ, __DAI_DSA_CORE, true, "SIGXFSZ", "File size limit exceeded"},

/*********************/
/* NON-POSIX SIGNALS */
/*********************/
#ifdef SIGCLD
    {SIGCLD, __DAI_DSA_IGNO, true, "SIGCLD", "Child stopped or terminated (Synonym for SIGCHLD)"},
#endif
#ifdef SIGEMT
    {SIGEMT, __DAI_DSA_CORE, true, "SIGEMT", "Emulator trap"},
#endif
#ifdef SIGINFO
    {SIGINFO, __DAI_DSA_TERM, true, "SIGINFO", "Power failure"},
#endif
#ifdef SIGIO
    {SIGIO, __DAI_DSA_TERM, true, "SIGIO", "I/O now possible"},
#endif
#ifdef SIGIOT
    {SIGIOT, __DAI_DSA_CORE, true, "SIGIOT", "IOT trap: Abort signal"},
#endif
#ifdef SIGLOST
    {SIGLOST, __DAI_DSA_TERM, true, "SIGLOST", "File lock lost"},
#endif
#ifdef SIGPWR
    {SIGPWR, __DAI_DSA_TERM, true, "SIGPWR", "Power failure"},
#endif
#ifdef SIGSTKFLT
    {SIGSTKFLT, __DAI_DSA_TERM, true, "SIGSTKFLT", "Stack fault on coprocessor"},
#endif
#ifdef SIGUNUSED
    {SIGUNUSED, __DAI_DSA_CORE, true, "SIGUNUSED", "Bad system call (Synonym for SIGSYS)"},
#endif
#ifdef SIGWINCH
    {SIGWINCH, __DAI_DSA_IGNO, true, "SIGWINCH", "Window resize signal"},
#endif
};

const size_t SIGLIST_LENGTH = sizeof(__Dai_siglist) / sizeof(__Dai_siglist[0]);

#endif  // SIGLIST_H_INCLUDED