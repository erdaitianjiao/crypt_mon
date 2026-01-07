#ifndef __CRYPTMON_H
#define __CRYPTMON_H

struct event {
    unsigned int pid;          
    unsigned long long duration_ns; 
    char comm[16];
	char cipher[32];  		// 加密算法名称
	unsigned long long crypt_time_ns;
	unsigned long long total_time_ns;

};

#endif
