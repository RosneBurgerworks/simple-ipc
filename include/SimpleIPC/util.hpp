/*
 * util.h
 *
 *  Created on: Mar 19, 2017
 *      Author: nullifiedcat
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <unistd.h>

struct proc_stat_s
{
    int pid;                                  // %d
    char comm[256];                           // %s
    char state;                               // %c
    int ppid;                                 // %d
    int pgrp;                                 // %d
    int session;                              // %d
    int tty_nr;                               // %d
    int tpgid;                                // %d
    unsigned long flags;                      // %lu OR %l
    unsigned long minflt;                     // %lu
    unsigned long cminflt;                    // %lu
    unsigned long majflt;                     // %lu
    unsigned long cmajflt;                    // %lu
    unsigned long utime;                      // %lu
    unsigned long stime;                      // %lu
    long cutime;                              // %ld
    long cstime;                              // %ld
    long priority;                            // %ld
    long nice;                                // %ld
    long num_threads;                         // %ld
    long itrealvalue;                         // %ld
    unsigned long starttime;                  // %lu
    unsigned long vsize;                      // %lu
    long rss;                                 // %ld
    unsigned long rlim;                       // %lu
    unsigned long startcode;                  // %lu
    unsigned long endcode;                    // %lu
    unsigned long startstack;                 // %lu
    unsigned long kstkesp;                    // %lu
    unsigned long kstkeip;                    // %lu
    unsigned long signal;                     // %lu
    unsigned long blocked;                    // %lu
    unsigned long sigignore;                  // %lu
    unsigned long sigcatch;                   // %lu
    unsigned long wchan;                      // %lu
    unsigned long nswap;                      // %lu
    unsigned long cnswap;                     // %lu
    int exit_signal;                          // %d
    int processor;                            // %d
    unsigned long rt_priority;                // %lu
    unsigned long policy;                     // %lu
    unsigned long long delayacct_blkio_ticks; // %llu
};

inline int read_stat(pid_t pid, struct proc_stat_s *s)
{
    static const char *const procfile = "/proc/%d/stat";
    static const char *const format   = "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu %llu";

    char buf[128];
    sprintf(buf, procfile, pid);

    FILE *proc = fopen(buf, "r");
    if (proc)
    {
        int ret = fscanf(proc, format, &s->pid, s->comm, &s->state, &s->ppid, &s->pgrp, &s->session, &s->tty_nr, &s->tpgid, &s->flags, &s->minflt, &s->cminflt, &s->majflt, &s->cmajflt, &s->utime, &s->stime, &s->cutime, &s->cstime, &s->priority, &s->nice, &s->num_threads, &s->itrealvalue, &s->starttime, &s->vsize, &s->rss, &s->rlim, &s->startcode, &s->endcode, &s->startstack, &s->kstkesp, &s->kstkeip, &s->signal, &s->blocked, &s->sigignore, &s->sigcatch, &s->wchan, &s->nswap, &s->cnswap, &s->exit_signal, &s->processor, &s->rt_priority, &s->policy, &s->delayacct_blkio_ticks);
        fclose(proc);
        if (ret == 42)
            return 1;
    }
    return 0;
}

#endif /* UTIL_H_ */