/*
 * util.h
 *
 * Created on: Mar 19, 2017
 * Author: nullifiedcat
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <unistd.h>

struct ProcessStat {
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

inline int readProcessStat(pid_t pid, struct ProcessStat *stat) {
    static const char *const procFilePath = "/proc/%d/stat";
    static const char *const format = "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %lu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu %llu";

    char buf[128];
    sprintf(buf, procFilePath, pid);

    FILE *procFile = fopen(buf, "r");
    if (procFile) {
        int ret = fscanf(procFile, format, &stat->pid, stat->comm, &stat->state, &stat->ppid, &stat->pgrp, &stat->session, &stat->tty_nr, &stat->tpgid, &stat->flags, &stat->minflt, &stat->cminflt, &stat->majflt, &stat->cmajflt, &stat->utime, &stat->stime, &stat->cutime, &stat->cstime, &stat->priority, &stat->nice, &stat->num_threads, &stat->itrealvalue, &stat->starttime, &stat->vsize, &stat->rss, &stat->rlim, &stat->startcode, &stat->endcode, &stat->startstack, &stat->kstkesp, &stat->kstkeip, &stat->signal, &stat->blocked, &stat->sigignore, &stat->sigcatch, &stat->wchan, &stat->nswap, &stat->cnswap, &stat->exit_signal, &stat->processor, &stat->rt_priority, &stat->policy, &stat->delayacct_blkio_ticks);
        fclose(procFile);
        if (ret == 42) {
            return 1;
        }
    }
    return 0;
}

#endif /* UTIL_H_ */
// lol