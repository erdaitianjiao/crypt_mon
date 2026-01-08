// #include "vmlinux.h"
#include "dm_crypt.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entery, struct crypt_config *cc)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
	
	char *crypt_name;
	if (bpf_probe_read_kernel(&crypt_name, sizeof(crypt_name), &cc->cipher_string) < 0) {
		return 0;
	} 
		
	char cipher_name[32] = {};
	if (crypt_name) {
		bpf_probe_read_kernel_str(cipher_name, sizeof(cipher_name), crypt_name);
	}
	
    // 在 /sys/kernel/debug/tracing/trace_pipe 中可以看到输出
    bpf_printk("crypt function enterd, called by pid %d\n", pid);
    bpf_printk("cryp: %s\n", cipher_name);
	return 0;
}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
		
	bpf_printk("crypt function exit, called by pid %d\n", pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
