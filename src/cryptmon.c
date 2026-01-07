#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cryptmon.h"
#include "cryptmon.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// 处理从内核传来的数据
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("PID: %-6u | COMM: %-16s | %-20s | Crypt: %7.2f us | Total: %8.2f us\n", 
           e->pid, e->comm, e->cipher, 
		   e->crypt_time_ns / 1000.0,
		   e->total_time_ns / 1000.0);
    return 0;
}

int main(int argc, char **argv) {
    struct cryptmon_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 打开并加载 BPF 骨架
    skel = cryptmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2. 附加挂载点
    err = cryptmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 3. 设置 Ring Buffer 监听
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Cryptmon started! Monitoring dm-crypt (crypt_convert) latency...\n");
    printf("%-10s | %-16s | %-15s\n", "PID", "COMM", "LATENCY");

    // 4. 循环读取数据
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    cryptmon_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
