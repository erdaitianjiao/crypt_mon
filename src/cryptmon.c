#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cryptmon.skel.h"

static volatile int stop = 0;
void sig_handler(int sig) { stop = 1; }

int main() {
    struct cryptmon_bpf *skel;
    int err;

    printf("crypt_mon is running...\n");
    signal(SIGINT, sig_handler);

    skel = cryptmon_bpf__open_and_load();
    if (!skel) return 1;

    err = cryptmon_bpf__attach(skel);
    if (err) goto cleanup; 

    while (!stop) {
        sleep(1);
    }

cleanup:
    cryptmon_bpf__destroy(skel);
    return 0;
}
