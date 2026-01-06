#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cryptmon.h"

// 记录进入时间
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID
    __type(value, u64); // 入口时间戳
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 进入加密核心函数
SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_enter)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);
    return 0;
}

// 离开加密核心函数
SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(crypt_convert_exit)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts, end_ts, duration;
    struct event *e;

    start_ts = bpf_map_lookup_elem(&start_times, &pid);
    if (!start_ts)
        return 0;

    end_ts = bpf_ktime_get_ns();
    duration = end_ts - *start_ts;

    // 填充数据发送给用户态
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->duration_ns = duration;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&start_times, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
