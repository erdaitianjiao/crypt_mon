#ifndef __CRYPTMON_H
#define __CRYPTMON_H

struct event {
    unsigned int pid;          
    unsigned long long duration_ns; 
    char comm[16];             
};

#endif
