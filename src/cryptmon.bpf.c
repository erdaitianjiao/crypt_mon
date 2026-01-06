#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
    unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("hello from pid %u\n", pid); 
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
